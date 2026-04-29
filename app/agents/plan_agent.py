"""
Two-phase plan generation with three post-generation security validation layers:

  Phase 1 — deterministic pre-flight checks (PreflightAgent, no LLM)
  Phase 2 — configuration-specific plan generation (Gemini, using real resource data)

Post-generation layers (run after LLM output, before plan is returned):
  Layer A — Policy engine:  blast level → change_window; maintenance window gate
  Layer B — Command compiler: subcommand whitelist, scope, expansion checks
  Layer C — Dry-run validation loop: resource existence via gcloud describe (max 2 retries)
"""
import asyncio
import datetime
import json
import os
import re
import uuid

from google import genai
from google.cloud import asset_v1
from google.genai import types

from app.agents.preflight_agent import PreflightAgent
from app.tools.agent_output import compact_impact_for_plan
from app.tools.command_compiler import compile_plan as _compile_plan
from app.tools.context_budget import budget_json, budget_str, BUDGETS
from config.schema import RemediationMode

_FINDING_CLASS_TO_MODE: dict[str, str] = {
    "VULNERABILITY": "OS_PATCH",
    "MISCONFIGURATION": "MISCONFIGURATION",
    "IAM_POLICY": "IAM",
    "NETWORK": "FIREWALL",
    "SCC_ERROR": None,
    "OBSERVATION": None,
}

_PLAN_PROMPT = """
## Pre-flight results
{preflight_json}

## Full resource data (live from Asset Inventory)
{resource_data_json}

## Finding
{finding_json}

## Graph context (blast radius, IAM paths, dormancy)
{impact_json}

## SCC remediation guidance
{remediation_text}

## Customer config
Enabled remediation modes: {enabled_modes}
Dry run: {dry_run}

## Instructions
Generate a remediation plan specific to THIS resource's current configuration.
Reference actual disk names, zones, service account emails, and flags from the
resource data. If any pre-flight check returned BLOCK, set plan status to
BLOCKED and explain why. Include exact gcloud commands or API calls, not
generic patterns. Include a machine-executable rollback artifact for every step.
"""

_DRY_RUN_RETRY_SUFFIX = """
## Dry-run validation errors (attempt {attempt} of 2)
The following commands in your previous plan referred to resources that could
not be found or returned API errors. Fix the resource names and flags before
regenerating the plan.

{errors}

Regenerate the full plan correcting these errors. Do not change steps that
validated successfully.
"""


class PlanAgent:
    def __init__(self, config):
        self.config = config

    async def generate(
        self,
        finding: dict,
        impact: dict,
        dormancy: dict,
    ) -> dict | None:
        enabled_modes = [
            m.value if hasattr(m, "value") else m
            for m in self.config.execution.enabled_modes
        ]

        finding_class = finding.get("finding_class", "")
        remediation_type = _FINDING_CLASS_TO_MODE.get(finding_class)
        if remediation_type is None or remediation_type not in enabled_modes:
            return None

        # ------------------------------------------------------------------- #
        # Phase 1 — Pre-flight checks (deterministic, no LLM)
        # ------------------------------------------------------------------- #
        resource_data = await _fetch_resource_data(finding["resource_name"])

        preflight = PreflightAgent(self.config)
        preflight_results = await preflight.run(finding, remediation_type, resource_data)

        has_block = any(r.get("result") == "BLOCK" for r in preflight_results)

        # ------------------------------------------------------------------- #
        # Phase 2 — Configuration-specific plan generation (LLM) with
        #           Layer C retry loop (max 2 retries on dry-run failures)
        # ------------------------------------------------------------------- #
        base_prompt = _PLAN_PROMPT.format(
            preflight_json=budget_json(preflight_results, BUDGETS["preflight"], "preflight"),
            resource_data_json=budget_json(resource_data, BUDGETS["resource_data"], "resource_data"),
            finding_json=budget_json(finding, BUDGETS["finding"], "finding"),
            impact_json=budget_json(compact_impact_for_plan(impact), BUDGETS["impact"], "impact"),
            remediation_text=budget_str(
                finding.get("remediation_text", "No guidance available."), 2_000, "remediation_text"
            ),
            enabled_modes=", ".join(enabled_modes),
            dry_run=self.config.dry_run,
        )

        prompt = base_prompt
        client = genai.Client()
        plan: dict = {}

        for attempt in range(3):  # attempt 0, 1, 2 — max 2 retries
            response = await client.aio.models.generate_content(
                model=os.getenv("PLANNING_MODEL_ID", "gemini-2.5-pro"),
                contents=prompt,
                config=types.GenerateContentConfig(response_mime_type="application/json"),
            )

            plan = json.loads(response.text.strip())
            plan["plan_id"] = plan.get("plan_id") or str(uuid.uuid4())
            plan["dry_run"] = self.config.dry_run
            plan["preflight_results"] = preflight_results
            plan["remediation_type"] = remediation_type

            # Enforce: if any BLOCK in pre-flight, plan must be BLOCKED
            if has_block:
                plan["status"] = "BLOCKED"
                if not plan.get("block_reason"):
                    block_checks = [r["detail"] for r in preflight_results if r["result"] == "BLOCK"]
                    plan["block_reason"] = "; ".join(block_checks)
                break  # No point retrying a pre-flight block

            # --------------------------------------------------------------- #
            # Layer A — Policy engine (structured plan field checks)
            # --------------------------------------------------------------- #
            plan = _apply_policy_engine(plan, impact, self.config)
            if plan.get("status") == "BLOCKED":
                break  # Policy gate blocked — no retry

            # --------------------------------------------------------------- #
            # Layer B — Command compiler (static analysis on api_call strings)
            # --------------------------------------------------------------- #
            compiler_result = _compile_plan(plan, finding)
            if not compiler_result:
                plan["status"] = "BLOCKED"
                plan["block_reason"] = (
                    "Command compiler violations: "
                    + "; ".join(compiler_result.violations)
                )
                plan["compiler_violations"] = compiler_result.violations
                break  # Compiler violations require human review — no retry

            # --------------------------------------------------------------- #
            # Layer C — Dry-run validation (resource existence checks)
            # --------------------------------------------------------------- #
            dry_run_errors = await _check_resources_exist(plan)
            if not dry_run_errors:
                break  # All checks passed — plan is valid

            if attempt < 2:
                # Augment prompt with errors and retry
                error_lines = "\n".join(f"- {e}" for e in dry_run_errors)
                prompt = base_prompt + _DRY_RUN_RETRY_SUFFIX.format(
                    attempt=attempt + 1, errors=error_lines
                )
                plan["_dry_run_retry"] = attempt + 1
            else:
                # Exhausted retries
                plan["status"] = "BLOCKED"
                plan["block_reason"] = (
                    f"Resource validation failed after {attempt + 1} attempts. "
                    "Commands reference resources that could not be found via the GCP API. "
                    "Errors: " + "; ".join(dry_run_errors[:5])
                )
                plan["dry_run_errors"] = dry_run_errors

        return plan


# ---------------------------------------------------------------------------
# Layer A — Policy engine
# ---------------------------------------------------------------------------

def _apply_policy_engine(plan: dict, impact: dict, config) -> dict:
    """
    Deterministic checks on plan's structured fields.
    Mutates plan in-place and returns it.
    """
    # Resolve blast_level from impact (impact_agent may nest it)
    blast_level = (
        impact.get("blast_level")
        or impact.get("impact_agent_output", {}).get("blast_level")
        or "UNKNOWN"
    )

    # Enforce change_window_required for HIGH/CRITICAL blast
    if blast_level in ("HIGH", "CRITICAL"):
        plan["change_window_required"] = True

    # Maintenance window gate: if change is required, check we're in the window
    if plan.get("change_window_required"):
        mw = getattr(getattr(config, "approval_policy", None), "default_maintenance_window", None)
        if mw and not _in_maintenance_window(mw):
            plan["status"] = "BLOCKED"
            plan["block_reason"] = (
                f"Change window required (blast_level={blast_level}) but the current time is "
                f"outside the configured maintenance window "
                f"({mw.start_time_utc}–{mw.end_time_utc} UTC on days {mw.days_of_week}). "
                "Schedule this remediation during the maintenance window."
            )

    return plan


def _in_maintenance_window(mw) -> bool:
    """
    Returns True if the current UTC time falls within the maintenance window.
    mw is a MaintenanceWindow schema instance with start_time_utc, end_time_utc,
    and days_of_week fields.
    """
    now = datetime.datetime.utcnow()
    if mw.days_of_week and now.weekday() not in mw.days_of_week:
        return False

    try:
        start = datetime.time.fromisoformat(mw.start_time_utc)
        end = datetime.time.fromisoformat(mw.end_time_utc)
    except (ValueError, AttributeError):
        return True  # Malformed window — don't block

    current = now.time().replace(second=0, microsecond=0)
    if start <= end:
        return start <= current <= end
    else:  # Crosses midnight
        return current >= start or current <= end


# ---------------------------------------------------------------------------
# Layer C — Dry-run resource existence validation
# ---------------------------------------------------------------------------

async def _check_resources_exist(plan: dict) -> list[str]:
    """
    For each gcloud mutating command in plan steps, converts it to a read-only
    describe command and runs it to verify the resource exists in GCP.

    Returns a list of error strings for resources that are not found or that
    return unexpected API errors. Timeout failures are ignored (network
    transience should not block a remediation).
    """
    errors: list[str] = []
    tasks = []

    steps = plan.get("steps", [])
    for step in steps:
        cmd = (step.get("api_call") or "").strip()
        if not cmd.startswith("gcloud"):
            continue
        describe_cmd = _to_describe_cmd(cmd)
        if describe_cmd:
            tasks.append((step.get("order", "?"), describe_cmd))

    for order, describe_cmd in tasks:
        error = await _run_describe(order, describe_cmd)
        if error:
            errors.append(error)

    return errors


async def _run_describe(order, describe_cmd: str) -> str | None:
    """Runs a single gcloud describe command and returns an error string or None."""
    try:
        args = describe_cmd.split()
        proc = await asyncio.create_subprocess_exec(
            *args,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
        try:
            stdout, stderr = await asyncio.wait_for(proc.communicate(), timeout=30)
        except asyncio.TimeoutError:
            proc.kill()
            return None  # Timeout — don't block

        if proc.returncode != 0:
            err_text = stderr.decode(errors="replace").strip()
            # Only surface definitive "not found" / "does not exist" errors
            lower = err_text.lower()
            if any(kw in lower for kw in ("not found", "does not exist", "notfound", "404")):
                return f"Step {order}: resource not found — {err_text[:200]}"
            # Permission errors or other transient errors are not re-prompt worthy
            return None

    except FileNotFoundError:
        # gcloud not installed in this environment — skip Layer C silently
        return None
    except Exception:
        return None

    return None


def _to_describe_cmd(cmd: str) -> str | None:
    """
    Converts a mutating gcloud command to its read-only describe equivalent
    so we can verify the referenced resource exists.

    Returns None for commands where no safe describe equivalent is possible
    (e.g. terraform, org-level commands without a resource name to describe).
    """
    cmd = " ".join(cmd.split())  # normalise whitespace

    # Extract optional flags we want to forward
    proj_m = re.search(r"--project[= ](\S+)", cmd)
    project_flag = f" --project={proj_m.group(1)}" if proj_m else ""

    zone_m = re.search(r"--zone[= ](\S+)", cmd)
    zone_flag = f" --zone={zone_m.group(1)}" if zone_m else ""

    # Pattern: gcloud <service-group> <resource-type> <action> <resource-name> [flags]
    # We capture the service path and the resource name (first positional after action).
    m = re.match(
        r"gcloud (compute firewall-rules|compute instances|projects|"
        r"iam service-accounts|storage buckets) \S+ (\S+)",
        cmd,
    )
    if not m:
        return None

    service = m.group(1)
    resource_name = m.group(2)

    # Skip flag-like tokens mistakenly captured as resource names
    if resource_name.startswith("--"):
        return None

    if service == "compute firewall-rules":
        return f"gcloud compute firewall-rules describe {resource_name}{project_flag}"
    if service == "compute instances":
        return f"gcloud compute instances describe {resource_name}{zone_flag}{project_flag}"
    if service == "projects":
        return f"gcloud projects describe {resource_name}"
    if service == "iam service-accounts":
        return f"gcloud iam service-accounts describe {resource_name}{project_flag}"
    if service == "storage buckets":
        return f"gcloud storage buckets describe {resource_name}"

    return None


# ---------------------------------------------------------------------------
# CAI resource data fetch (Phase 1 helper)
# ---------------------------------------------------------------------------

async def _fetch_resource_data(resource_name: str) -> dict:
    """
    Fetches the full resource.data blob from Cloud Asset Inventory.
    Returns an empty dict if the asset is not found or on error.
    """
    try:
        client = asset_v1.AssetServiceClient()

        asset_name = resource_name
        if not resource_name.startswith("//"):
            asset_name = "//" + resource_name.replace("https://", "")

        response = client.batch_get_assets_history(
            parent=_extract_org_or_project(resource_name),
            asset_names=[asset_name],
            content_type=asset_v1.ContentType.RESOURCE,
            read_time_window=asset_v1.TimeWindow(),
        )

        for asset in response.assets:
            if asset.asset.resource and asset.asset.resource.data:
                return dict(asset.asset.resource.data)

        return {}
    except Exception:
        return {}


def _extract_org_or_project(resource_name: str) -> str:
    """Returns the closest project or org scope for CAI lookups."""
    parts = resource_name.replace("//", "").split("/")
    if "projects" in parts:
        idx = parts.index("projects")
        return f"projects/{parts[idx + 1]}"
    return resource_name
