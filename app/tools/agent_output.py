"""
Subagent output schemas and compaction helpers.

Implements the "sub-agents return only summaries to the parent" principle from
the Claude Code harness architecture (arXiv 2604.14228). Each compaction function
strips fields that the downstream consumer never reads, reducing both Python
memory and the token cost when data is serialised into subsequent prompts.

Compaction functions are pure (no side effects) and each documents exactly which
fields the named consumer actually uses, so drift is immediately visible.

Consumers:
    compact_impact_for_plan()     → PlanAgent.generate()     (LLM prompt injection)
    compact_impact_for_approval() → dispatch_approval_request()  (card rendering)
    compact_impact_for_scoring()  → compute_confidence_score()   (scalar scalars only)
    compact_plan_for_verify()     → VerifyAgent.verify()     (verification + regression)
"""


# ---------------------------------------------------------------------------
# ImpactAgent → PlanAgent
# ---------------------------------------------------------------------------

def compact_impact_for_plan(impact: dict) -> dict:
    """
    Returns the impact fields needed for remediation plan generation.

    PlanAgent uses: blast_level, asset_env, asset_team, prod_blast_count,
    pii_blast_count, internet_exposed, iam_lateral_paths, downstream_resources,
    blast_radius_assets, network_exposure_summary.

    Strips: full network_exposure_details object, upstream_dependencies,
    shared_dependency_exposure, service_account_chain (retained in blast_radius_assets).
    Downstream_resources reduced from full objects → {name, env, team} summaries.
    Average size reduction: ~65% on a typical 20-resource blast radius.
    """
    return {
        "asset_name":    impact.get("asset_name"),
        "asset_env":     impact.get("asset_env"),
        "asset_team":    impact.get("asset_team"),
        "blast_level":   impact.get("blast_level"),
        "total_downstream":  impact.get("total_downstream"),
        "prod_blast_count":  impact.get("prod_blast_count"),
        "pii_blast_count":   impact.get("pii_blast_count"),
        "internet_exposed":  impact.get("internet_exposed"),
        "high_criticality_upstream_count": impact.get("high_criticality_upstream_count"),
        # Resource objects → name+env+team only (drops selfLink, metadata, labels, etc.)
        "downstream_resources": [
            {
                "name": r.get("name") or r.get("asset_name", ""),
                "env":  r.get("env", "unknown"),
                "team": r.get("team", "unknown"),
            }
            for r in impact.get("downstream_resources", [])[:10]   # 10 instead of 20
        ],
        # IAM paths: keep first 5 (not 10) — LLM doesn't improve plans from >5 paths
        "iam_lateral_paths": impact.get("iam_lateral_paths", [])[:5],
        # Asset names only (strings), used for blast radius scope in plan
        "blast_radius_assets": impact.get("blast_radius_assets", [])[:30],
        # Network: summary dict only, not the full exposure details object
        "network_exposure_summary": _summarise_network(impact.get("network_exposure_details")),
    }


# ---------------------------------------------------------------------------
# ImpactAgent → approval_tools.dispatch_approval_request()
# ---------------------------------------------------------------------------

def compact_impact_for_approval(impact: dict) -> dict:
    """
    Returns the impact fields required for approval card rendering.

    approval_tools uses: blast_level, blast_radius_assets, prod_blast_count,
    pii_blast_count, asset_env, asset_team, internet_exposed.

    Strips all graph traversal lists — approval cards never render them.
    """
    return {
        "blast_level":         impact.get("blast_level"),
        "blast_radius_assets": impact.get("blast_radius_assets", [])[:50],
        "prod_blast_count":    impact.get("prod_blast_count", 0),
        "pii_blast_count":     impact.get("pii_blast_count", 0),
        "asset_env":           impact.get("asset_env"),
        "asset_team":          impact.get("asset_team"),
        "internet_exposed":    impact.get("internet_exposed", False),
    }


# ---------------------------------------------------------------------------
# ImpactAgent → confidence scoring (main.py)
# ---------------------------------------------------------------------------

def compact_impact_for_scoring(impact: dict) -> dict:
    """
    Returns the scalar fields needed by compute_confidence_score() and
    _determine_execution_tier(). Everything else is noise for this consumer.
    """
    return {
        "blast_level":   impact.get("blast_level"),
        "dormancy_class": impact.get("dormancy_class", "ACTIVE"),
    }


# ---------------------------------------------------------------------------
# PlanAgent → VerifyAgent
# ---------------------------------------------------------------------------

def compact_plan_for_verify(plan: dict) -> dict:
    """
    Returns the plan fields required for post-execution verification.

    VerifyAgent.verify() uses:
      - remediation_type    → selects the verification handler
      - finding_id          → SCC fallback polling + muting
      - asset_name          → graph state update + regression monitor scope
      - cve_ids             → OS_PATCH: confirm CVEs cleared
      - connectivity_test_cases → FIREWALL: NIC connectivity test spec
      - iam_member / iam_role   → IAM: analyzeIamPolicy call
      - blast_radius_assets     → regression monitor asset scope
      - dry_run             → suppress mute_resolved_finding in dry-run

    Strips: steps, rollback_steps, preflight_results, confidence_score,
    summary, risk_assessment, plan_summary — none read by verify().
    Typical plan dict is 3–8 KB; verify context is <500 bytes.
    """
    return {
        "plan_id":                 plan.get("plan_id"),
        "finding_id":              plan.get("finding_id"),
        "asset_name":              plan.get("asset_name"),
        "remediation_type":        plan.get("remediation_type"),
        # OS_PATCH
        "cve_ids":                 plan.get("cve_ids", []),
        # FIREWALL
        "connectivity_test_cases": plan.get("connectivity_test_cases", []),
        # IAM
        "iam_member":              plan.get("iam_member"),
        "iam_role":                plan.get("iam_role"),
        # Regression monitor — asset names only, capped to avoid huge lists
        "blast_radius_assets":     plan.get("blast_radius_assets", [])[:50],
        # Misc
        "dry_run":                 plan.get("dry_run", False),
    }


# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------

def _summarise_network(details: dict | None) -> dict:
    """Reduces network_exposure_details to a 3-field summary."""
    if not details:
        return {}
    return {
        "internet_exposed": details.get("internet_exposed"),
        "exposed_ports":    details.get("exposed_ports", [])[:10],
        "exposure_type":    details.get("exposure_type"),
    }
