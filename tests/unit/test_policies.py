"""
Unit tests for config/policies.py — ExecutionPolicy.matches().

Pure method tests — no database or API calls.
"""
import pytest
from config.policies import ExecutionPolicy, LabelCondition


def _policy(**overrides) -> ExecutionPolicy:
    base = dict(
        policy_id="p1",
        customer_id="test",
        name="Test Policy",
        remediation_type="OS_PATCH",
        severity_levels=["CRITICAL", "HIGH"],
        tier=1,
        active=True,
    )
    base.update(overrides)
    return ExecutionPolicy(**base)


def _finding(**overrides) -> dict:
    base = dict(
        finding_id="f1",
        finding_class="VULNERABILITY",
        severity="CRITICAL",
        category="OS_VULNERABILITY",
        resource_labels={},
    )
    base.update(overrides)
    return base


# ---------------------------------------------------------------------------
# Active flag
# ---------------------------------------------------------------------------

def test_inactive_policy_never_matches():
    policy = _policy(active=False)
    assert not policy.matches(_finding(), "LOW")

def test_active_policy_can_match():
    policy = _policy()
    assert policy.matches(_finding(), "LOW")


# ---------------------------------------------------------------------------
# Remediation type matching (via finding_class mapping)
# ---------------------------------------------------------------------------

def test_vulnerability_maps_to_os_patch():
    policy = _policy(remediation_type="OS_PATCH")
    assert policy.matches(_finding(finding_class="VULNERABILITY"), "LOW")

def test_misconfiguration_maps_to_misconfiguration():
    policy = _policy(remediation_type="MISCONFIGURATION")
    assert policy.matches(_finding(finding_class="MISCONFIGURATION"), "LOW")

def test_iam_policy_maps_to_iam():
    policy = _policy(remediation_type="IAM", severity_levels=["HIGH"])
    assert policy.matches(_finding(finding_class="IAM_POLICY", severity="HIGH"), "LOW")

def test_network_maps_to_firewall():
    policy = _policy(remediation_type="FIREWALL", severity_levels=["HIGH"])
    assert policy.matches(_finding(finding_class="NETWORK", severity="HIGH"), "LOW")

def test_wrong_remediation_type_no_match():
    policy = _policy(remediation_type="IAM")
    assert not policy.matches(_finding(finding_class="VULNERABILITY"), "LOW")


# ---------------------------------------------------------------------------
# Severity matching
# ---------------------------------------------------------------------------

def test_matching_severity_passes():
    policy = _policy(severity_levels=["HIGH"])
    assert policy.matches(_finding(severity="HIGH"), "LOW")

def test_severity_not_in_list_fails():
    policy = _policy(severity_levels=["CRITICAL"])
    assert not policy.matches(_finding(severity="HIGH"), "LOW")

def test_multiple_severities_any_match():
    policy = _policy(severity_levels=["CRITICAL", "HIGH", "MEDIUM"])
    assert policy.matches(_finding(severity="MEDIUM"), "LOW")


# ---------------------------------------------------------------------------
# Finding category filter
# ---------------------------------------------------------------------------

def test_empty_categories_matches_all():
    policy = _policy(finding_categories=[])
    assert policy.matches(_finding(category="OS_VULNERABILITY"), "LOW")
    assert policy.matches(_finding(category="CONTAINER_VULNERABILITY"), "LOW")

def test_category_filter_match():
    policy = _policy(finding_categories=["OS_VULNERABILITY"])
    assert policy.matches(_finding(category="OS_VULNERABILITY"), "LOW")

def test_category_filter_no_match():
    policy = _policy(finding_categories=["OS_VULNERABILITY"])
    assert not policy.matches(_finding(category="CONTAINER_VULNERABILITY"), "LOW")


# ---------------------------------------------------------------------------
# Blast radius cap
# ---------------------------------------------------------------------------

def test_blast_at_max_allowed_passes():
    policy = _policy(max_blast_radius="MEDIUM")
    assert policy.matches(_finding(), "MEDIUM")

def test_blast_below_max_passes():
    policy = _policy(max_blast_radius="MEDIUM")
    assert policy.matches(_finding(), "LOW")

def test_blast_above_max_fails():
    policy = _policy(max_blast_radius="MEDIUM")
    assert not policy.matches(_finding(), "HIGH")

def test_blast_critical_always_blocked_by_low_cap():
    policy = _policy(max_blast_radius="LOW")
    for level in ("MEDIUM", "HIGH", "CRITICAL"):
        assert not policy.matches(_finding(), level)


# ---------------------------------------------------------------------------
# Asset label conditions
# ---------------------------------------------------------------------------

def test_no_label_conditions_always_pass():
    policy = _policy(asset_label_conditions=[])
    assert policy.matches(_finding(resource_labels={}), "LOW")

def test_single_label_condition_match():
    policy = _policy(asset_label_conditions=[LabelCondition(key="env", value="dev")])
    assert policy.matches(_finding(resource_labels={"env": "dev"}), "LOW")

def test_single_label_condition_wrong_value():
    policy = _policy(asset_label_conditions=[LabelCondition(key="env", value="dev")])
    assert not policy.matches(_finding(resource_labels={"env": "prod"}), "LOW")

def test_single_label_condition_missing_key():
    policy = _policy(asset_label_conditions=[LabelCondition(key="env", value="dev")])
    assert not policy.matches(_finding(resource_labels={}), "LOW")

def test_multiple_label_conditions_all_must_match():
    policy = _policy(asset_label_conditions=[
        LabelCondition(key="env", value="dev"),
        LabelCondition(key="team", value="platform"),
    ])
    # Both present and correct
    assert policy.matches(_finding(resource_labels={"env": "dev", "team": "platform"}), "LOW")
    # One missing
    assert not policy.matches(_finding(resource_labels={"env": "dev"}), "LOW")
    # One wrong value
    assert not policy.matches(_finding(resource_labels={"env": "dev", "team": "security"}), "LOW")


# ---------------------------------------------------------------------------
# Combined multi-condition scenarios
# ---------------------------------------------------------------------------

def test_tier1_dev_patch_policy():
    """Typical Tier 1 policy: OS_PATCH, dev env, LOW blast, HIGH severity."""
    policy = _policy(
        remediation_type="OS_PATCH",
        severity_levels=["HIGH", "CRITICAL"],
        asset_label_conditions=[LabelCondition(key="env", value="dev")],
        max_blast_radius="LOW",
        min_confidence_threshold=0.90,
        tier=1,
    )
    assert policy.matches(
        _finding(
            finding_class="VULNERABILITY",
            severity="HIGH",
            resource_labels={"env": "dev"},
        ),
        "LOW",
    )

def test_all_conditions_fail_independently():
    """Each condition independently vetoes the match."""
    policy = _policy(
        remediation_type="OS_PATCH",
        severity_levels=["HIGH"],
        asset_label_conditions=[LabelCondition(key="env", value="dev")],
        max_blast_radius="LOW",
    )
    # Wrong remediation type
    assert not policy.matches(_finding(finding_class="IAM_POLICY", severity="HIGH",
                                       resource_labels={"env": "dev"}), "LOW")
    # Wrong severity
    assert not policy.matches(_finding(finding_class="VULNERABILITY", severity="MEDIUM",
                                       resource_labels={"env": "dev"}), "LOW")
    # Wrong label
    assert not policy.matches(_finding(finding_class="VULNERABILITY", severity="HIGH",
                                       resource_labels={"env": "prod"}), "LOW")
    # Blast too high
    assert not policy.matches(_finding(finding_class="VULNERABILITY", severity="HIGH",
                                       resource_labels={"env": "dev"}), "MEDIUM")
