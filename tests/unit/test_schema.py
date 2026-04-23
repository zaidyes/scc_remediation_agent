import pytest
from config.schema import (
    ScopeConfig, LabelFilter, SeverityThreshold, CustomerConfig,
    ApprovalPolicy, ApprovalTier, Approver, MaintenanceWindow,
    ExecutionConfig, NotificationConfig, FindingFilters,
)


# ---------------------------------------------------------------------------
# SeverityThreshold.to_api_values
# ---------------------------------------------------------------------------

def test_severity_critical_only():
    assert SeverityThreshold.CRITICAL_ONLY.to_api_values() == ["CRITICAL"]

def test_severity_high_plus():
    assert SeverityThreshold.HIGH_PLUS.to_api_values() == ["CRITICAL", "HIGH"]

def test_severity_medium_plus():
    assert SeverityThreshold.MEDIUM_PLUS.to_api_values() == ["CRITICAL", "HIGH", "MEDIUM"]

def test_severity_all():
    assert SeverityThreshold.ALL.to_api_values() == ["CRITICAL", "HIGH", "MEDIUM", "LOW"]


# ---------------------------------------------------------------------------
# ScopeConfig.matches_asset
# ---------------------------------------------------------------------------

def _scope(**kwargs) -> ScopeConfig:
    return ScopeConfig(**kwargs)


def test_scope_empty_matches_everything():
    scope = _scope()
    assert scope.matches_asset({"project": "any-project", "labels": {}})

def test_scope_project_filter_match():
    scope = _scope(project_ids=["my-project"])
    assert scope.matches_asset({"project": "my-project", "labels": {}})

def test_scope_project_filter_no_match():
    scope = _scope(project_ids=["my-project"])
    assert not scope.matches_asset({"project": "other-project", "labels": {}})

def test_scope_include_label_match():
    scope = _scope(include_labels=[LabelFilter(key="env", value="prod")])
    assert scope.matches_asset({"project": "p", "labels": {"env": "prod"}})

def test_scope_include_label_no_match():
    scope = _scope(include_labels=[LabelFilter(key="env", value="prod")])
    assert not scope.matches_asset({"project": "p", "labels": {"env": "dev"}})

def test_scope_include_label_missing():
    scope = _scope(include_labels=[LabelFilter(key="env", value="prod")])
    assert not scope.matches_asset({"project": "p", "labels": {}})

def test_scope_exclude_label_match():
    scope = _scope(exclude_labels=[LabelFilter(key="skip-remediation", value="true")])
    assert not scope.matches_asset({"project": "p", "labels": {"skip-remediation": "true"}})

def test_scope_exclude_label_no_match():
    scope = _scope(exclude_labels=[LabelFilter(key="skip-remediation", value="true")])
    assert scope.matches_asset({"project": "p", "labels": {"env": "prod"}})

def test_scope_combined_project_and_label():
    scope = _scope(
        project_ids=["prod-project"],
        include_labels=[LabelFilter(key="env", value="prod")],
        exclude_labels=[LabelFilter(key="change-freeze", value="true")],
    )
    # All conditions met
    assert scope.matches_asset({"project": "prod-project", "labels": {"env": "prod"}})
    # Wrong project
    assert not scope.matches_asset({"project": "dev-project", "labels": {"env": "prod"}})
    # Excluded label present
    assert not scope.matches_asset({"project": "prod-project", "labels": {"env": "prod", "change-freeze": "true"}})

def test_scope_multiple_include_labels_all_must_match():
    scope = _scope(include_labels=[
        LabelFilter(key="env", value="prod"),
        LabelFilter(key="team", value="platform"),
    ])
    assert scope.matches_asset({"project": "p", "labels": {"env": "prod", "team": "platform"}})
    assert not scope.matches_asset({"project": "p", "labels": {"env": "prod"}})
    assert not scope.matches_asset({"project": "p", "labels": {"team": "platform"}})


# ---------------------------------------------------------------------------
# CustomerConfig — Pydantic validation
# ---------------------------------------------------------------------------

def _minimal_config(**overrides) -> dict:
    base = {
        "customer_id": "test-customer",
        "org_id": "123456789",
        "display_name": "Test",
        "scope": {},
        "approval_policy": {
            "tiers": [],
            "approvers": [],
            "default_maintenance_window": {
                "days_of_week": [1, 2, 3, 4],
                "start_time_utc": "02:00",
                "end_time_utc": "05:00",
            },
        },
    }
    base.update(overrides)
    return base

def test_customer_config_defaults_dry_run():
    config = CustomerConfig(**_minimal_config())
    assert config.dry_run is True

def test_customer_config_default_severity():
    config = CustomerConfig(**_minimal_config())
    assert config.severity_threshold == SeverityThreshold.HIGH_PLUS

def test_customer_config_dry_run_overridable():
    config = CustomerConfig(**_minimal_config(dry_run=False))
    assert config.dry_run is False
