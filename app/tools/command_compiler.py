"""
command_compiler.py — deterministic pre-execution validation of LLM-generated
remediation commands.

Runs between plan_agent output and user presentation / approval dispatch.
Zero LLM calls. Returns a CompilerResult that callers use to set
plan["status"] = "BLOCKED" when violations are found.

Three checks per api_call string:
  1. Subcommand whitelist  — is this a known, permitted gcloud/terraform command?
  2. Project scope         — does --project match the finding's project?
  3. Destructive/expansion — does the command expand access or delete resources?
"""
import re
import shlex
from dataclasses import dataclass, field


# ---------------------------------------------------------------------------
# Result type
# ---------------------------------------------------------------------------

@dataclass
class CompilerResult:
    passed: bool
    violations: list[str] = field(default_factory=list)

    def __bool__(self) -> bool:
        return self.passed


# ---------------------------------------------------------------------------
# Allowed subcommand prefixes per remediation type
# ---------------------------------------------------------------------------
# Only commands that *restrict* or *patch* are permitted.
# Read-only commands (describe/list/get) are always allowed.
# Anything else is a violation.

_READONLY_PREFIXES = (
    "gcloud compute firewall-rules describe",
    "gcloud compute firewall-rules list",
    "gcloud projects get-iam-policy",
    "gcloud organizations get-iam-policy",
    "gcloud resource-manager folders get-iam-policy",
    "gcloud iam service-accounts get-iam-policy",
    "gcloud compute instances describe",
    "gcloud compute instances list",
    "gcloud compute os-config patch-jobs list",
    "gcloud compute os-config patch-jobs describe",
    "gcloud asset search-all-resources",
    "terraform show",
    "terraform state list",
    "terraform plan",
    "terraform validate",
)

_ALLOWED_MUTATING: dict[str, tuple[str, ...]] = {
    "FIREWALL": (
        "gcloud compute firewall-rules update",
    ),
    "IAM": (
        "gcloud projects remove-iam-policy-binding",
        "gcloud organizations remove-iam-policy-binding",
        "gcloud resource-manager folders remove-iam-policy-binding",
        "gcloud iam service-accounts remove-iam-policy-binding",
        "gcloud projects set-iam-policy",      # allowed only with patch file
    ),
    "OS_PATCH": (
        "gcloud compute os-config patch-jobs execute",
        "gcloud compute os-config patch-deployments create",
        "gcloud compute os-config patch-deployments update",
    ),
    "MISCONFIGURATION": (
        "gcloud compute firewall-rules update",
        "gcloud projects remove-iam-policy-binding",
        "gcloud organizations remove-iam-policy-binding",
        "gcloud storage buckets update",
        "gcloud compute instances add-metadata",
        "gcloud compute instances remove-metadata",
        "gcloud compute ssl-policies update",
        "gcloud compute target-https-proxies update",
        "gcloud compute backend-services update",
        "terraform apply",
    ),
}

# ---------------------------------------------------------------------------
# Hard-blocked patterns regardless of remediation type
# ---------------------------------------------------------------------------

_BLOCKED_SUBCOMMANDS = (
    # Deletion of core resources — should never be a remediation step
    "gcloud compute firewall-rules delete",
    "gcloud compute instances delete",
    "gcloud compute disks delete",
    "gcloud compute networks delete",
    "gcloud compute subnetworks delete",
    "gcloud projects delete",
    "gcloud organizations delete",
    "gcloud iam service-accounts delete",
    "gsutil rm -r",
    "gsutil rm -ra",
    # Full policy replacement — replaces the entire IAM policy, too broad
    "gcloud organizations set-iam-policy",
    # Terraform destroy is never a remediation action
    "terraform destroy",
)

# For firewall rules: expanding source ranges to the internet is never safe
_FIREWALL_EXPANSION_PATTERNS = (
    re.compile(r"--source-ranges[= ]['\"]?0\.0\.0\.0/0"),
    re.compile(r"--source-ranges[= ]['\"]?::/0"),
    re.compile(r"--source-ranges[= ]['\"]?0\.0\.0\.0/0,::/0"),
)

# For IAM: adding bindings is not a remediation action
_IAM_EXPANSION_PREFIXES = (
    "gcloud projects add-iam-policy-binding",
    "gcloud organizations add-iam-policy-binding",
    "gcloud resource-manager folders add-iam-policy-binding",
    "gcloud iam service-accounts add-iam-policy-binding",
)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _extract_project_from_resource(resource_name: str) -> str | None:
    """Extracts project ID from an SCC resource_name."""
    m = re.search(r"projects/([^/]+)", resource_name)
    return m.group(1) if m else None


def _extract_project_from_cmd(cmd: str) -> str | None:
    """Extracts --project value from a gcloud command string."""
    m = re.search(r"--project[= ](['\"]?)(\S+)\1", cmd)
    return m.group(2).rstrip(",;") if m else None


def _normalise(cmd: str) -> str:
    """Collapse whitespace and lower-case for prefix matching."""
    return " ".join(cmd.split()).lower()


def _starts_with_any(cmd: str, prefixes: tuple[str, ...]) -> bool:
    norm = _normalise(cmd)
    return any(norm.startswith(p.lower()) for p in prefixes)


# ---------------------------------------------------------------------------
# Core compiler
# ---------------------------------------------------------------------------

def compile_plan(plan: dict, finding: dict) -> CompilerResult:
    """
    Validates every api_call in plan["steps"] and plan["rollback_steps"].

    Returns CompilerResult(passed=True) when all checks pass.
    Returns CompilerResult(passed=False, violations=[...]) on any failure.
    """
    remediation_type = plan.get("remediation_type", "MISCONFIGURATION")
    resource_name    = plan.get("asset_name") or finding.get("resource_name", "")
    finding_project  = _extract_project_from_resource(resource_name)

    allowed_mutating = _ALLOWED_MUTATING.get(remediation_type, ())
    violations: list[str] = []

    all_steps = list(plan.get("steps", [])) + list(plan.get("rollback_steps", []))

    for step in all_steps:
        cmd = (step.get("api_call") or "").strip()
        if not cmd:
            continue

        order = step.get("order", "?")

        # ── 1. Hard-blocked subcommands ───────────────────────────────────
        if _starts_with_any(cmd, _BLOCKED_SUBCOMMANDS):
            violations.append(
                f"Step {order}: command '{cmd[:80]}' is blocked — "
                "deletion and full policy replacement are not permitted remediation actions."
            )
            continue

        # ── 2. IAM expansion ──────────────────────────────────────────────
        if _starts_with_any(cmd, _IAM_EXPANSION_PREFIXES):
            violations.append(
                f"Step {order}: command '{cmd[:80]}' adds an IAM binding — "
                "remediation must restrict access, not expand it."
            )
            continue

        # ── 3. Firewall expansion (opening to the internet) ───────────────
        if remediation_type in ("FIREWALL", "MISCONFIGURATION"):
            for pattern in _FIREWALL_EXPANSION_PATTERNS:
                if pattern.search(cmd):
                    violations.append(
                        f"Step {order}: command sets source-ranges to 0.0.0.0/0 or ::/0 — "
                        "this opens the firewall to all internet traffic, which is the "
                        "finding being remediated, not a fix."
                    )
                    break

        # ── 4. Subcommand whitelist ────────────────────────────────────────
        if cmd.startswith("gcloud") or cmd.startswith("terraform"):
            is_readonly  = _starts_with_any(cmd, _READONLY_PREFIXES)
            is_allowed   = _starts_with_any(cmd, allowed_mutating)
            if not is_readonly and not is_allowed:
                # Build a helpful hint listing what IS allowed
                allowed_hint = ", ".join(f"`{p}`" for p in allowed_mutating[:4])
                violations.append(
                    f"Step {order}: command '{cmd[:80]}' is not in the permitted "
                    f"command list for {remediation_type} remediation. "
                    f"Allowed mutating commands: {allowed_hint}."
                )

        # ── 5. Project scope ──────────────────────────────────────────────
        if finding_project and cmd.startswith("gcloud"):
            cmd_project = _extract_project_from_cmd(cmd)
            if cmd_project and cmd_project != finding_project:
                violations.append(
                    f"Step {order}: command targets project '{cmd_project}' but the "
                    f"finding is in project '{finding_project}' — possible scope creep."
                )

    if violations:
        return CompilerResult(passed=False, violations=violations)
    return CompilerResult(passed=True)
