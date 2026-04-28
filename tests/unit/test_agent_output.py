"""
Unit tests for app/tools/agent_output.py — all four compaction functions.

All functions are pure; no mocks needed.
"""
import pytest
from app.tools.agent_output import (
    compact_impact_for_plan,
    compact_impact_for_approval,
    compact_impact_for_scoring,
    compact_plan_for_verify,
)


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

def _full_impact(**overrides):
    base = {
        "asset_name": "//compute.googleapis.com/projects/p/instances/vm1",
        "asset_env": "prod",
        "asset_team": "platform",
        "asset_owner": "owner@x.com",
        "blast_level": "HIGH",
        "total_downstream": 15,
        "prod_blast_count": 5,
        "pii_blast_count": 2,
        "internet_exposed": True,
        "high_criticality_upstream_count": 3,
        "downstream_resources": [
            {"name": f"vm-{i}", "env": "prod", "team": "infra",
             "selfLink": "https://...", "metadata": {"foo": "bar"}}
            for i in range(15)
        ],
        "iam_lateral_paths": [{"path": f"path-{i}"} for i in range(8)],
        "blast_radius_assets": [f"asset-{i}" for i in range(40)],
        "network_exposure_details": {
            "internet_exposed": True,
            "exposed_ports": list(range(20)),
            "exposure_type": "DIRECT",
            "extra_field": "should_be_stripped",
        },
        "upstream_dependencies": [{"name": "dep"}],
        "shared_dependency_exposure": [{"name": "shared"}],
        "service_account_chain": [{"sa": "sa@p.iam"}],
        "dormancy_class": "ACTIVE",
    }
    base.update(overrides)
    return base


def _full_plan(**overrides):
    base = {
        "plan_id": "plan-123",
        "finding_id": "find-001",
        "asset_name": "//compute.googleapis.com/projects/p/instances/vm1",
        "remediation_type": "OS_PATCH",
        "cve_ids": ["CVE-2024-1234"],
        "connectivity_test_cases": [{"source_ip": "10.0.0.1", "dest_ip": "10.0.0.2"}],
        "iam_member": "user:a@x.com",
        "iam_role": "roles/editor",
        "blast_radius_assets": [f"asset-{i}" for i in range(60)],
        "dry_run": False,
        # Fields that should be stripped:
        "steps": [{"order": 1, "action": "run_patch", "command": "gcloud ..."}],
        "rollback_steps": [{"order": 1, "action": "rollback", "command": "gcloud ..."}],
        "preflight_results": [{"check": "freeze", "result": "PASS"}],
        "confidence_score": 0.92,
        "summary": "Apply patch for CVE-2024-1234",
        "risk_assessment": "Low risk — dormant asset",
        "plan_summary": "One-step patch",
        "block_reason": None,
    }
    base.update(overrides)
    return base


# ---------------------------------------------------------------------------
# compact_impact_for_plan
# ---------------------------------------------------------------------------

def test_plan_compaction_keeps_required_fields():
    result = compact_impact_for_plan(_full_impact())
    for key in ("asset_name", "asset_env", "asset_team", "blast_level",
                "total_downstream", "prod_blast_count", "pii_blast_count",
                "internet_exposed", "high_criticality_upstream_count",
                "downstream_resources", "iam_lateral_paths",
                "blast_radius_assets", "network_exposure_summary"):
        assert key in result, f"missing key: {key}"

def test_plan_compaction_strips_noise_fields():
    result = compact_impact_for_plan(_full_impact())
    for stripped in ("asset_owner", "network_exposure_details",
                     "upstream_dependencies", "shared_dependency_exposure",
                     "service_account_chain"):
        assert stripped not in result, f"should be stripped: {stripped}"

def test_plan_downstream_capped_at_10():
    result = compact_impact_for_plan(_full_impact())
    assert len(result["downstream_resources"]) == 10

def test_plan_downstream_reduced_to_name_env_team():
    result = compact_impact_for_plan(_full_impact())
    for r in result["downstream_resources"]:
        assert set(r.keys()) == {"name", "env", "team"}
        assert "selfLink" not in r
        assert "metadata" not in r

def test_plan_iam_paths_capped_at_5():
    result = compact_impact_for_plan(_full_impact())
    assert len(result["iam_lateral_paths"]) == 5

def test_plan_blast_radius_capped_at_30():
    result = compact_impact_for_plan(_full_impact())
    assert len(result["blast_radius_assets"]) == 30

def test_plan_network_exposure_summary_has_3_fields():
    result = compact_impact_for_plan(_full_impact())
    summary = result["network_exposure_summary"]
    assert set(summary.keys()) == {"internet_exposed", "exposed_ports", "exposure_type"}
    assert "extra_field" not in summary

def test_plan_network_exposed_ports_capped_at_10():
    result = compact_impact_for_plan(_full_impact())
    assert len(result["network_exposure_summary"]["exposed_ports"]) == 10

def test_plan_network_summary_empty_when_no_details():
    result = compact_impact_for_plan(_full_impact(network_exposure_details=None))
    assert result["network_exposure_summary"] == {}

def test_plan_compaction_handles_missing_fields_gracefully():
    result = compact_impact_for_plan({})
    assert result["blast_level"] is None
    assert result["downstream_resources"] == []
    assert result["iam_lateral_paths"] == []


# ---------------------------------------------------------------------------
# compact_impact_for_approval
# ---------------------------------------------------------------------------

def test_approval_keeps_7_fields():
    result = compact_impact_for_approval(_full_impact())
    expected_keys = {
        "blast_level", "blast_radius_assets", "prod_blast_count",
        "pii_blast_count", "asset_env", "asset_team", "internet_exposed",
    }
    assert set(result.keys()) == expected_keys

def test_approval_strips_graph_traversal():
    result = compact_impact_for_approval(_full_impact())
    for stripped in ("downstream_resources", "iam_lateral_paths",
                     "network_exposure_details", "upstream_dependencies"):
        assert stripped not in result

def test_approval_blast_radius_capped_at_50():
    result = compact_impact_for_approval(_full_impact())
    assert len(result["blast_radius_assets"]) == 50

def test_approval_defaults_for_empty_input():
    result = compact_impact_for_approval({})
    assert result["prod_blast_count"] == 0
    assert result["pii_blast_count"] == 0
    assert result["internet_exposed"] is False


# ---------------------------------------------------------------------------
# compact_impact_for_scoring
# ---------------------------------------------------------------------------

def test_scoring_keeps_only_2_fields():
    result = compact_impact_for_scoring(_full_impact())
    assert set(result.keys()) == {"blast_level", "dormancy_class"}

def test_scoring_strips_everything_else():
    result = compact_impact_for_scoring(_full_impact())
    for stripped in ("asset_name", "downstream_resources", "iam_lateral_paths",
                     "internet_exposed", "network_exposure_details"):
        assert stripped not in result

def test_scoring_dormancy_defaults_to_active():
    result = compact_impact_for_scoring({})
    assert result["dormancy_class"] == "ACTIVE"

def test_scoring_blast_level_none_when_missing():
    result = compact_impact_for_scoring({})
    assert result["blast_level"] is None


# ---------------------------------------------------------------------------
# compact_plan_for_verify
# ---------------------------------------------------------------------------

def test_verify_keeps_required_fields():
    result = compact_plan_for_verify(_full_plan())
    for key in ("plan_id", "finding_id", "asset_name", "remediation_type",
                "cve_ids", "connectivity_test_cases", "iam_member", "iam_role",
                "blast_radius_assets", "dry_run"):
        assert key in result, f"missing key: {key}"

def test_verify_strips_execution_fields():
    result = compact_plan_for_verify(_full_plan())
    for stripped in ("steps", "rollback_steps", "preflight_results",
                     "confidence_score", "summary", "risk_assessment",
                     "plan_summary", "block_reason"):
        assert stripped not in result, f"should be stripped: {stripped}"

def test_verify_blast_radius_capped_at_50():
    result = compact_plan_for_verify(_full_plan())
    assert len(result["blast_radius_assets"]) == 50

def test_verify_dry_run_defaults_to_false():
    result = compact_plan_for_verify({})
    assert result["dry_run"] is False

def test_verify_empty_lists_default_correctly():
    result = compact_plan_for_verify({})
    assert result["cve_ids"] == []
    assert result["connectivity_test_cases"] == []
    assert result["blast_radius_assets"] == []

def test_verify_result_is_much_smaller_than_input():
    full = _full_plan()
    compacted = compact_plan_for_verify(full)
    # Verify dict should have fewer keys
    assert len(compacted) < len(full)
    # Specifically: 10 keys
    assert len(compacted) == 10
