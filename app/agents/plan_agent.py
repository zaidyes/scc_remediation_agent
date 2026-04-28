"""
Two-phase plan generation:
  Phase 1 — deterministic pre-flight checks (PreflightAgent, no LLM)
  Phase 2 — configuration-specific plan generation (Gemini, using real resource data)
"""
import json
import os
import uuid

from google import genai
from google.cloud import asset_v1
from google.genai import types

from app.agents.preflight_agent import PreflightAgent
from app.tools.agent_output import compact_impact_for_plan
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
        # Phase 2 — Configuration-specific plan generation (LLM)
        # ------------------------------------------------------------------- #
        prompt = _PLAN_PROMPT.format(
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

        client = genai.Client()
        response = await client.aio.models.generate_content(
            model=os.getenv("PLANNING_MODEL_ID", "gemini-3.1-pro-preview"),
            contents=prompt,
            config=types.GenerateContentConfig(response_mime_type="application/json"),
        )

        plan = json.loads(response.text.strip())
        plan["plan_id"] = plan.get("plan_id") or str(uuid.uuid4())
        plan["dry_run"] = self.config.dry_run
        plan["preflight_results"] = preflight_results
        plan["remediation_type"] = remediation_type

        # Enforce: if any BLOCK in pre-flight, plan must be BLOCKED regardless
        # of what the LLM returned
        if has_block:
            plan["status"] = "BLOCKED"
            if not plan.get("block_reason"):
                block_checks = [r["detail"] for r in preflight_results if r["result"] == "BLOCK"]
                plan["block_reason"] = "; ".join(block_checks)

        return plan


async def _fetch_resource_data(resource_name: str) -> dict:
    """
    Fetches the full resource.data blob from Cloud Asset Inventory.
    Returns an empty dict if the asset is not found or on error.
    """
    try:
        client = asset_v1.AssetServiceClient()

        # CAI asset names use the //service/... format
        # resource_name from SCC may already be in that format or may be
        # a REST resource path — normalise either way
        asset_name = resource_name
        if not resource_name.startswith("//"):
            # Convert REST resource path to CAI asset name format
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
