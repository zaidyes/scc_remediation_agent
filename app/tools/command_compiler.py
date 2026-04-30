"""
command_compiler.py — deterministic pre-execution validation of LLM-generated
remediation commands.

Runs between plan_agent output and user presentation / approval dispatch.
Zero LLM calls. Returns a CompilerResult that callers use to set
plan["status"] = "BLOCKED" when violations are found.

Two public entry points:

  compile_plan(plan, finding)
      Validates plan["steps"] only — the forward remediation commands.
      Checks: intent alignment, hard-blocked subcommands, IAM expansion,
      firewall expansion, subcommand whitelist, project scope.

  validate_rollback_steps(plan, finding)
      Validates plan["rollback_steps"] with a separate, permissive whitelist
      that allows inverse commands (e.g. add-iam-policy-binding to restore a
      removed binding).  Also enforces a pairing check: each rollback command
      must reference a resource that appears in a forward step.
      Hard-blocked subcommands (deletion, destroy) are still blocked.

Keeping the two validators separate is intentional: a command that is a
violation in a forward step (adding an IAM binding) is the correct inverse
action in a rollback step.
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
# Rollback-allowed commands per remediation type
# ---------------------------------------------------------------------------
# These are the logical inverses of the forward allowed commands.
# add-iam-policy-binding is allowed here (blocked in forward steps) because
# rollback for an IAM remediation must restore the binding that was removed.
# Pairing validation (see validate_rollback_steps) ensures each command
# targets a resource that was actually touched by a forward step.

_ALLOWED_ROLLBACK: dict[str, tuple[str, ...]] = {
    "IAM": (
        "gcloud projects add-iam-policy-binding",
        "gcloud organizations add-iam-policy-binding",
        "gcloud resource-manager folders add-iam-policy-binding",
        "gcloud iam service-accounts add-iam-policy-binding",
        "gcloud projects set-iam-policy",          # restore from saved policy file
    ),
    "FIREWALL": (
        "gcloud compute firewall-rules update",    # restore prior rule config
        "gcloud compute firewall-rules import",    # import config saved to GCS
    ),
    "OS_PATCH": (
        "gcloud compute disks create",             # restore disk from snapshot
        "gcloud compute instances start",          # restart if stopped during patch
    ),
    "MISCONFIGURATION": (
        "gcloud compute firewall-rules update",
        "gcloud compute firewall-rules import",
        "gcloud projects add-iam-policy-binding",
        "gcloud organizations add-iam-policy-binding",
        "gcloud storage buckets update",
        "gcloud compute instances add-metadata",
        "gcloud compute instances remove-metadata",
        "gcloud compute ssl-policies update",
        "gcloud compute target-https-proxies update",
        "gcloud compute backend-services update",
        "terraform apply",
    ),
}

# Hard-blocked even in rollback context — deletion is never a valid restore
_ROLLBACK_HARD_BLOCKED = (
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
    "terraform destroy",
    # Full org policy replacement — too broad even as rollback;
    # use add-iam-policy-binding to restore specific bindings instead
    "gcloud organizations set-iam-policy",
)

# Tokens that are gcloud subcommand keywords, not resource identifiers.
# Used by _primary_resource_token to find the first real resource name in a cmd.
_GCLOUD_KEYWORDS = frozenset({
    "gcloud", "terraform", "gh",
    "compute", "projects", "organizations", "iam", "resource-manager",
    "folders", "storage", "firewall-rules", "instances", "service-accounts",
    "os-config", "patch-jobs", "patch-deployments", "ssl-policies",
    "target-https-proxies", "backend-services", "buckets", "disks",
    "snapshots", "networks", "subnetworks",
    "update", "create", "delete", "import", "export", "describe", "list",
    "execute", "start", "apply", "plan", "show", "validate",
    "add-iam-policy-binding", "remove-iam-policy-binding",
    "set-iam-policy", "get-iam-policy",
    "pr", "revert",
})


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
# Check 4b — Argument-level guards for high-blast commands
# ---------------------------------------------------------------------------
# These run after the whitelist check (the command is already confirmed to be
# an allowed mutating command) to enforce that the specific arguments used
# don't widen the blast radius back to an unsafe level.

def _check_set_iam_policy_args(cmd: str, order) -> str | None:
    """
    gcloud projects set-iam-policy replaces the *entire* project IAM policy.
    It must be called with an explicit file path — not stdin ('-'), which
    allows piped or heredoc content that is harder to audit.

    Valid:   gcloud projects set-iam-policy my-project policy.json
    Invalid: gcloud projects set-iam-policy my-project          (no file → reads stdin)
    Invalid: gcloud projects set-iam-policy my-project -        (explicit stdin)

    Returns a violation string or None if the command is acceptable.
    """
    if "set-iam-policy" not in cmd:
        return None

    try:
        tokens = shlex.split(cmd)
    except ValueError:
        return None

    try:
        idx = next(i for i, t in enumerate(tokens) if t == "set-iam-policy")
    except StopIteration:
        return None

    # Positional args after "set-iam-policy": first is project ID, second is file
    positionals = [t for t in tokens[idx + 1:] if not t.startswith("-")]

    if len(positionals) < 2:
        return (
            f"Step {order}: gcloud projects set-iam-policy requires an explicit policy "
            "file argument (e.g. policy.json). Without a file the command reads from "
            "stdin — supply a file path to make the policy change auditable."
        )

    if positionals[1] == "-":
        return (
            f"Step {order}: gcloud projects set-iam-policy with '-' reads the policy "
            "from stdin, which is not permitted — use an explicit file path instead."
        )

    return None


def _check_terraform_apply_args(cmd: str, order) -> str | None:
    """
    terraform apply without a -target flag or a plan file applies *all* pending
    changes in the Terraform state, which is too broad for a single remediation
    action and may change unrelated resources.

    Valid:   terraform apply -target=google_compute_firewall.rule
    Valid:   terraform apply remediation.tfplan
    Invalid: terraform apply
    Invalid: terraform apply -auto-approve

    Returns a violation string or None if the command is acceptable.
    """
    if not _normalise(cmd).startswith("terraform apply"):
        return None

    try:
        tokens = shlex.split(cmd)
    except ValueError:
        tokens = cmd.split()

    # -target or --target scopes the apply to a specific resource
    has_target = any(
        t.startswith("-target") or t.startswith("--target") for t in tokens
    )
    if has_target:
        return None

    # A positional argument after 'apply' is a plan file
    try:
        idx = tokens.index("apply")
    except ValueError:
        return None

    positionals = [t for t in tokens[idx + 1:] if not t.startswith("-")]
    if positionals:
        return None  # Plan file present — scoped apply

    return (
        f"Step {order}: terraform apply without a -target flag or plan file will apply "
        "all pending state changes — use -target=<resource_type.resource_name> or "
        "supply an explicit .tfplan file to scope the apply to the remediated resource."
    )


# ---------------------------------------------------------------------------
# Core compiler
# ---------------------------------------------------------------------------

# ---------------------------------------------------------------------------
# Check 0 — Intent alignment
# ---------------------------------------------------------------------------
# Maps the finding's finding_class to the remediation_type the plan should
# have.  A mismatch is a signal that the plan was generated for the wrong
# finding, or that a prompt injection redirected the model to a different
# action class.
# ---------------------------------------------------------------------------

_FINDING_CLASS_TO_REMEDIATION_TYPE: dict[str, str] = {
    "VULNERABILITY":    "OS_PATCH",
    "MISCONFIGURATION": "MISCONFIGURATION",
    "IAM_POLICY":       "IAM",
    "NETWORK":          "FIREWALL",
}


def compile_plan(plan: dict, finding: dict) -> CompilerResult:
    """
    Validates every api_call in plan["steps"] (forward steps only).
    Rollback steps are validated separately by validate_rollback_steps().

    Returns CompilerResult(passed=True) when all checks pass.
    Returns CompilerResult(passed=False, violations=[...]) on any failure.
    """
    remediation_type = plan.get("remediation_type", "MISCONFIGURATION")
    resource_name    = plan.get("asset_name") or finding.get("resource_name", "")
    finding_project  = _extract_project_from_resource(resource_name)

    allowed_mutating = _ALLOWED_MUTATING.get(remediation_type, ())
    violations: list[str] = []

    # ── 0. Intent alignment ───────────────────────────────────────────────
    finding_class = finding.get("finding_class", "")
    expected_type = _FINDING_CLASS_TO_REMEDIATION_TYPE.get(finding_class)
    if expected_type and remediation_type != expected_type:
        violations.append(
            f"Plan remediation_type '{remediation_type}' does not match "
            f"finding_class '{finding_class}' (expected '{expected_type}'). "
            "Possible prompt injection or misrouted plan."
        )
        # Return immediately — mismatched type means the per-type whitelist
        # checks below would use the wrong allowed set.
        return CompilerResult(passed=False, violations=violations)

    for step in plan.get("steps", []):
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

        # ── 4b. Argument-level guards ──────────────────────────────────────
        v = _check_set_iam_policy_args(cmd, order)
        if v:
            violations.append(v)
        v = _check_terraform_apply_args(cmd, order)
        if v:
            violations.append(v)

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


# ---------------------------------------------------------------------------
# Rollback step validator
# ---------------------------------------------------------------------------

def _primary_resource_token(cmd: str) -> str | None:
    """
    Returns the first non-keyword, non-flag token from a gcloud/gh command —
    typically the resource name (project ID, firewall rule name, instance name).

    Used for pairing: verify a rollback command targets something that was
    touched by a forward step.
    """
    try:
        tokens = shlex.split(cmd)
    except ValueError:
        tokens = cmd.split()
    for token in tokens:
        if not token.startswith("-") and token not in _GCLOUD_KEYWORDS and len(token) >= 2:
            return token
    return None


def validate_rollback_steps(plan: dict, finding: dict) -> CompilerResult:
    """
    Validates plan["rollback_steps"] with rollback-specific rules:

      1. Hard-blocked subcommands — deletion and destroy are never valid
      2. Rollback whitelist — only known inverse commands per remediation type
      3. Project scope — --project must match the finding's project
      4. Pairing check — each rollback command's primary resource token must
         appear in at least one forward step's api_call (IAM and FIREWALL only)

    Returns CompilerResult(passed=True) when all checks pass.
    """
    remediation_type  = plan.get("remediation_type", "MISCONFIGURATION")
    resource_name     = plan.get("asset_name") or finding.get("resource_name", "")
    finding_project   = _extract_project_from_resource(resource_name)
    allowed_rollback  = _ALLOWED_ROLLBACK.get(remediation_type, ())
    violations: list[str] = []

    # Pre-compute forward step commands for pairing check
    forward_cmds = " ".join(
        (s.get("api_call") or "") for s in plan.get("steps", [])
    )

    for step in plan.get("rollback_steps", []):
        cmd = (step.get("api_call") or "").strip()
        if not cmd:
            continue

        order = step.get("order", "?")

        # ── 1. Hard-blocked subcommands ───────────────────────────────────
        if _starts_with_any(cmd, _ROLLBACK_HARD_BLOCKED):
            violations.append(
                f"Rollback step {order}: command '{cmd[:80]}' is hard-blocked — "
                "deletion and full policy replacement are not valid rollback actions."
            )
            continue

        # ── 2. Rollback whitelist ─────────────────────────────────────────
        if cmd.startswith("gcloud") or cmd.startswith("terraform"):
            is_readonly = _starts_with_any(cmd, _READONLY_PREFIXES)
            is_allowed  = _starts_with_any(cmd, allowed_rollback)
            if not is_readonly and not is_allowed:
                allowed_hint = ", ".join(f"`{p}`" for p in allowed_rollback[:4])
                violations.append(
                    f"Rollback step {order}: command '{cmd[:80]}' is not in the permitted "
                    f"rollback command list for {remediation_type}. "
                    f"Allowed rollback commands: {allowed_hint}."
                )
                continue

        # ── 2b. Argument-level guards (same rules apply in rollback context) ─
        v = _check_set_iam_policy_args(cmd, order)
        if v:
            violations.append(v.replace("Step", "Rollback step", 1))
        v = _check_terraform_apply_args(cmd, order)
        if v:
            violations.append(v.replace("Step", "Rollback step", 1))

        # ── 3. Project scope ──────────────────────────────────────────────
        if finding_project and cmd.startswith("gcloud"):
            cmd_project = _extract_project_from_cmd(cmd)
            if cmd_project and cmd_project != finding_project:
                violations.append(
                    f"Rollback step {order}: command targets project '{cmd_project}' but the "
                    f"finding is in project '{finding_project}' — possible scope creep."
                )

        # ── 4. Pairing check (IAM and FIREWALL) ───────────────────────────
        # For these types, the resource being restored should match a resource
        # modified in the forward steps. OS_PATCH rollback restores a snapshot
        # (different resource name by design) so pairing is skipped.
        if remediation_type in ("IAM", "FIREWALL"):
            resource_token = _primary_resource_token(cmd)
            if resource_token and resource_token not in forward_cmds:
                violations.append(
                    f"Rollback step {order}: resource '{resource_token}' does not appear "
                    "in any forward step — rollback command may reference an unrelated resource."
                )

    if violations:
        return CompilerResult(passed=False, violations=violations)
    return CompilerResult(passed=True)
