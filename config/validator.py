from config.schema import CustomerConfig

# This requires the graph queries and scc_tools to be implemented.
# We will mock the external dependencies for now to satisfy the validator structure.

def _extract_project(asset_name: str) -> str:
    parts = asset_name.split("/")
    if "projects" in parts:
        idx = parts.index("projects")
        return parts[idx + 1]
    return "unknown"

async def validate_and_preview(config: CustomerConfig) -> dict:
    """
    Runs a dry simulation of the config against current findings and assets.
    Returns a preview dict for display in the UI before activation.
    Returns errors if config is invalid (e.g., no approvers for critical findings).
    """
    errors = []
    warnings = []

    # Validate: critical findings must have an approver
    has_critical_approver = any(
        "CRITICAL" in a.severity_levels for a in config.approval_policy.approvers
    )
    if not has_critical_approver and config.severity_threshold in ["CRITICAL_ONLY", "HIGH_PLUS"]:
        errors.append("No approver configured for CRITICAL severity findings.")

    # Validate: auto-approve tier requires auto_approve_enabled
    auto_tiers = [t for t in config.approval_policy.tiers if t.auto_approve_eligible]
    if auto_tiers and not config.approval_policy.auto_approve_enabled:
        warnings.append("Auto-approve tiers defined but auto_approve_enabled is False.")

    try:
        from graph.queries.preview import count_in_scope_assets
        asset_count = await count_in_scope_assets(config.scope, config.org_id)
    except ImportError:
        asset_count = 0 # Stub

    try:
        from app.tools.scc_tools import list_active_findings
        findings = list(list_active_findings(config.org_id, config.severity_threshold.to_api_values()))
        in_scope_findings = [f for f in findings if config.scope.matches_asset({"project": _extract_project(f["resource_name"]), "labels": {}})]
    except ImportError:
        in_scope_findings = []

    auto_approve_count = 0   # would need graph query to estimate

    return {
        "valid": len(errors) == 0,
        "errors": errors,
        "warnings": warnings,
        "preview": {
            "assets_in_scope": asset_count,
            "active_findings_in_scope": len(in_scope_findings),
            "estimated_auto_approve": auto_approve_count,
            "dry_run_active": config.dry_run,
        }
    }
