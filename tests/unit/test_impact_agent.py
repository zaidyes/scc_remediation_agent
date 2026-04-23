import pytest
from unittest.mock import patch

from app.agents.impact_agent import ImpactAgent
from config.schema import CustomerConfig, ScopeConfig, ApprovalPolicy, MaintenanceWindow


def _make_config():
    return CustomerConfig(
        customer_id="test",
        org_id="123456789",
        display_name="Test",
        scope=ScopeConfig(),
        approval_policy=ApprovalPolicy(
            tiers=[], approvers=[],
            default_maintenance_window=MaintenanceWindow(
                days_of_week=[1], start_time_utc="02:00", end_time_utc="05:00"
            ),
        ),
    )


def _run(downstream, iam_paths=None, metadata=None, network=None):
    config = _make_config()
    finding = {"resource_name": "//compute.googleapis.com/projects/p/instances/vm1"}

    with patch("app.agents.impact_agent.query_blast_radius", return_value=downstream), \
         patch("app.agents.impact_agent.query_iam_paths", return_value=iam_paths or []), \
         patch("app.agents.impact_agent.get_resource_metadata", return_value=metadata or {}), \
         patch("app.agents.impact_agent.get_network_exposure", return_value=network or {"internet_exposed": False}):

        import asyncio
        return asyncio.run(ImpactAgent(config).analyse(finding))


def test_blast_level_low_no_downstream():
    result = _run(downstream=[])
    assert result["blast_level"] == "LOW"
    assert result["prod_blast_count"] == 0

def test_blast_level_medium_one_prod():
    downstream = [{"env": "prod", "data_class": "internal"}]
    result = _run(downstream=downstream)
    assert result["blast_level"] == "MEDIUM"

def test_blast_level_high_four_prod():
    downstream = [{"env": "prod", "data_class": "internal"}] * 4
    result = _run(downstream=downstream)
    assert result["blast_level"] == "HIGH"

def test_blast_level_high_pii_downstream():
    downstream = [{"env": "dev", "data_class": "pii"}]
    result = _run(downstream=downstream)
    assert result["blast_level"] == "HIGH"

def test_blast_level_critical_eleven_prod():
    downstream = [{"env": "prod", "data_class": "internal"}] * 11
    result = _run(downstream=downstream)
    assert result["blast_level"] == "CRITICAL"

def test_blast_level_medium_asset_is_prod():
    result = _run(downstream=[], metadata={"env": "prod"})
    assert result["blast_level"] == "MEDIUM"

def test_downstream_capped_at_20_in_result():
    downstream = [{"env": "dev", "data_class": "internal"}] * 30
    result = _run(downstream=downstream)
    assert len(result["downstream_resources"]) == 20

def test_internet_exposed_propagated():
    result = _run(downstream=[], network={"internet_exposed": True, "open_ports": [22, 443]})
    assert result["internet_exposed"] is True
