import json
import pytest
from pathlib import Path
from unittest.mock import patch, MagicMock

from app.agents.triage_agent import TriageAgent, _deduplicate
from config.schema import (
    CustomerConfig, ScopeConfig, LabelFilter, SeverityThreshold,
    FindingFilters, ApprovalPolicy, MaintenanceWindow,
)

FIXTURES = Path(__file__).parent.parent / "fixtures"


def _load_findings():
    with open(FIXTURES / "mock_findings.json") as f:
        return json.load(f)


def _make_config(**overrides) -> CustomerConfig:
    base = {
        "customer_id": "test",
        "org_id": "123456789",
        "display_name": "Test",
        "scope": ScopeConfig(project_ids=["prod-project-1", "dev-project-1"]),
        "severity_threshold": SeverityThreshold.HIGH_PLUS,
        "filters": FindingFilters(
            require_active_exposure_path=False,
            deduplicate_across_scanners=True,
            exclude_accepted_risks=True,
        ),
        "approval_policy": ApprovalPolicy(
            tiers=[],
            approvers=[],
            default_maintenance_window=MaintenanceWindow(
                days_of_week=[1, 2, 3, 4],
                start_time_utc="02:00",
                end_time_utc="05:00",
            ),
        ),
    }
    base.update(overrides)
    return CustomerConfig(**base)


# ---------------------------------------------------------------------------
# _deduplicate
# ---------------------------------------------------------------------------

def test_deduplicate_removes_exact_duplicate():
    findings = [
        {"resource_name": "//x", "category": "OS_VULNERABILITY", "cve_ids": ["CVE-2024-1234"]},
        {"resource_name": "//x", "category": "OS_VULNERABILITY", "cve_ids": ["CVE-2024-1234"]},
    ]
    assert len(_deduplicate(findings)) == 1

def test_deduplicate_keeps_different_resource():
    findings = [
        {"resource_name": "//x", "category": "OS_VULNERABILITY", "cve_ids": []},
        {"resource_name": "//y", "category": "OS_VULNERABILITY", "cve_ids": []},
    ]
    assert len(_deduplicate(findings)) == 2

def test_deduplicate_keys_on_cve_set_order():
    findings = [
        {"resource_name": "//x", "category": "OS_VULNERABILITY", "cve_ids": ["CVE-B", "CVE-A"]},
        {"resource_name": "//x", "category": "OS_VULNERABILITY", "cve_ids": ["CVE-A", "CVE-B"]},
    ]
    assert len(_deduplicate(findings)) == 1

def test_deduplicate_keeps_different_category():
    findings = [
        {"resource_name": "//x", "category": "OS_VULNERABILITY", "cve_ids": []},
        {"resource_name": "//x", "category": "OPEN_FIREWALL", "cve_ids": []},
    ]
    assert len(_deduplicate(findings)) == 2


# ---------------------------------------------------------------------------
# TriageAgent.run — filtering logic (graph + SCC mocked)
# ---------------------------------------------------------------------------

def _mock_scope_status(in_scope_projects):
    def _impl(asset_name, scope_config):
        for proj in in_scope_projects:
            if f"/projects/{proj}/" in asset_name:
                return {"in_scope": True}
        return {"in_scope": False}
    return _impl


@pytest.mark.asyncio
async def test_triage_filters_out_of_scope():
    findings = _load_findings()
    config = _make_config()

    with patch("app.agents.triage_agent.list_active_findings", return_value=iter(findings)), \
         patch("app.agents.triage_agent.get_resource_scope_status",
               side_effect=_mock_scope_status(["prod-project-1", "dev-project-1"])):

        agent = TriageAgent(config)
        result = await agent.run()

    # find-005 is on out-of-scope-project — should be excluded
    names = [f["finding_id"] for f in result]
    assert "find-005" not in names


@pytest.mark.asyncio
async def test_triage_deduplicates():
    findings = _load_findings()
    config = _make_config()

    with patch("app.agents.triage_agent.list_active_findings", return_value=iter(findings)), \
         patch("app.agents.triage_agent.get_resource_scope_status",
               side_effect=_mock_scope_status(["prod-project-1", "dev-project-1"])):

        agent = TriageAgent(config)
        result = await agent.run()

    # find-001 and find-006 are duplicates (same resource+category+CVEs); only one should survive
    ids = [f["finding_id"] for f in result]
    assert not ("find-001" in ids and "find-006" in ids), "Duplicate findings not deduplicated"


@pytest.mark.asyncio
async def test_triage_ranks_by_attack_exposure():
    findings = _load_findings()
    config = _make_config()

    with patch("app.agents.triage_agent.list_active_findings", return_value=iter(findings)), \
         patch("app.agents.triage_agent.get_resource_scope_status",
               side_effect=_mock_scope_status(["prod-project-1", "dev-project-1"])):

        agent = TriageAgent(config)
        result = await agent.run()

    scores = [f.get("attack_exposure_score", 0) for f in result]
    assert scores == sorted(scores, reverse=True)


@pytest.mark.asyncio
async def test_triage_exposure_path_filter():
    """With require_active_exposure_path=True, find-004 (NOT_EXPOSED) should be dropped."""
    findings = _load_findings()
    config = _make_config(
        filters=FindingFilters(require_active_exposure_path=True)
    )

    with patch("app.agents.triage_agent.list_active_findings", return_value=iter(findings)), \
         patch("app.agents.triage_agent.get_resource_scope_status",
               side_effect=_mock_scope_status(["prod-project-1", "dev-project-1"])):

        agent = TriageAgent(config)
        result = await agent.run()

    ids = [f["finding_id"] for f in result]
    assert "find-004" not in ids
