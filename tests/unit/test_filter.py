"""
Unit tests for graph/events/filter.py — classify_change().

All logic is in-memory; no database or API calls.
"""
import pytest
from graph.events.filter import classify_change, PROXIMITY_HOPS, IAM_PROXIMITY_HOPS


# ---------------------------------------------------------------------------
# Helpers for building synthetic CAI / audit events
# ---------------------------------------------------------------------------

def _iam_event(current_bindings, prior_bindings=None):
    """Builds a CAI IAM_POLICY content-type event."""
    def _bindings(pairs):
        # pairs: list of (role, [member, ...])
        return {"bindings": [{"role": r, "members": m} for r, m in pairs]}

    return {
        "asset": {
            "name": "//cloudresourcemanager.googleapis.com/projects/p",
            "assetType": "cloudresourcemanager.googleapis.com/Project",
            "contentType": "IAM_POLICY",
            "iamPolicy": _bindings(current_bindings),
        },
        "priorAsset": {
            "iamPolicy": _bindings(prior_bindings),
        } if prior_bindings is not None else {},
    }


def _resource_event(curr_data, prior_data=None, asset_type="compute.googleapis.com/Instance"):
    return {
        "asset": {
            "name": "//compute.googleapis.com/projects/p/instances/vm1",
            "assetType": asset_type,
            "contentType": "RESOURCE",
            "resource": {"data": curr_data},
        },
        "priorAsset": {
            "resource": {"data": prior_data},
        } if prior_data is not None else {},
    }


def _audit_event(method):
    return {
        "protoPayload": {
            "methodName": method,
            "resourceName": "//compute.googleapis.com/projects/p/instances/vm1",
        }
    }


# ---------------------------------------------------------------------------
# Stage 1 — IAM_POLICY events
# ---------------------------------------------------------------------------

def test_iam_bindings_changed_returns_iam_type():
    event = _iam_event(
        current_bindings=[("roles/editor", ["user:a@x.com"])],
        prior_bindings=[],
    )
    result = classify_change(event)
    assert result is not None
    assert result["change_type"] == "IAM_POLICY"

def test_iam_only_etag_changed_discarded():
    # Identical bindings — only etag changed
    bindings = [("roles/viewer", ["user:a@x.com"])]
    event = _iam_event(current_bindings=bindings, prior_bindings=bindings)
    assert classify_change(event) is None

def test_iam_no_prior_treated_as_new_binding():
    event = _iam_event(
        current_bindings=[("roles/owner", ["serviceAccount:sa@p.iam.gserviceaccount.com"])],
    )
    result = classify_change(event)
    assert result is not None
    assert result["change_type"] == "IAM_POLICY"


# ---------------------------------------------------------------------------
# Stage 1 — RESOURCE deletion
# ---------------------------------------------------------------------------

def test_deletion_detected_when_asset_has_no_resource():
    event = {
        "asset": {
            "name": "//compute.googleapis.com/projects/p/instances/vm1",
            "assetType": "compute.googleapis.com/Instance",
            "contentType": "RESOURCE",
            # No "resource" key — asset deleted
        },
        "priorAsset": {"resource": {"data": {"status": "RUNNING"}}},
    }
    result = classify_change(event)
    assert result is not None
    assert result["change_type"] == "deletion"

def test_deletion_without_prior_discarded():
    # No prior asset — this is a new creation, not deletion
    event = _resource_event({"status": "RUNNING"}, prior_data=None)
    result = classify_change(event)
    # Status change or None — depends on prior data; what matters: NOT a deletion
    if result:
        assert result["change_type"] != "deletion"


# ---------------------------------------------------------------------------
# Stage 1 — RESOURCE status changes
# ---------------------------------------------------------------------------

def test_status_change_running_to_stopped():
    event = _resource_event(
        curr_data={"status": "STOPPED"},
        prior_data={"status": "RUNNING"},
    )
    result = classify_change(event)
    assert result is not None
    assert result["change_type"] == "status_change"

def test_same_status_not_a_status_change():
    event = _resource_event(
        curr_data={"status": "RUNNING"},
        prior_data={"status": "RUNNING"},
    )
    assert classify_change(event) is None


# ---------------------------------------------------------------------------
# Stage 1 — Critical label changes
# ---------------------------------------------------------------------------

def test_env_label_change_detected():
    event = _resource_event(
        curr_data={"labels": {"env": "prod"}},
        prior_data={"labels": {"env": "dev"}},
    )
    result = classify_change(event)
    assert result is not None
    assert result["change_type"] == "critical_label_change"

def test_change_freeze_label_added():
    event = _resource_event(
        curr_data={"labels": {"change-freeze": "true"}},
        prior_data={"labels": {}},
    )
    result = classify_change(event)
    assert result is not None
    assert result["change_type"] == "critical_label_change"

def test_non_critical_label_change_discarded():
    event = _resource_event(
        curr_data={"labels": {"app-version": "2.0"}},
        prior_data={"labels": {"app-version": "1.0"}},
    )
    assert classify_change(event) is None


# ---------------------------------------------------------------------------
# Stage 1 — Service account changes
# ---------------------------------------------------------------------------

def test_service_account_change_detected():
    event = _resource_event(
        curr_data={"serviceAccount": "new-sa@p.iam.gserviceaccount.com"},
        prior_data={"serviceAccount": "old-sa@p.iam.gserviceaccount.com"},
    )
    result = classify_change(event)
    assert result is not None
    assert result["change_type"] == "service_account_change"

def test_gce_sa_list_change_detected():
    event = _resource_event(
        curr_data={"serviceAccounts": [{"email": "new@p.iam.gserviceaccount.com"}]},
        prior_data={"serviceAccounts": [{"email": "old@p.iam.gserviceaccount.com"}]},
    )
    result = classify_change(event)
    assert result is not None
    assert result["change_type"] == "service_account_change"


# ---------------------------------------------------------------------------
# Stage 1 — Firewall rule changes
# ---------------------------------------------------------------------------

def test_firewall_rule_change_detected():
    event = _resource_event(
        curr_data={"allowed": [{"IPProtocol": "tcp", "ports": ["0-65535"]}]},
        prior_data={"allowed": [{"IPProtocol": "tcp", "ports": ["443"]}]},
        asset_type="compute.googleapis.com/Firewall",
    )
    result = classify_change(event)
    assert result is not None
    assert result["change_type"] == "firewall_rule_change"

def test_firewall_data_unchanged_discarded():
    data = {"allowed": [{"IPProtocol": "tcp", "ports": ["443"]}]}
    event = _resource_event(curr_data=data, prior_data=data,
                             asset_type="compute.googleapis.com/Firewall")
    assert classify_change(event) is None


# ---------------------------------------------------------------------------
# Stage 1 — Audit log events
# ---------------------------------------------------------------------------

def test_audit_set_iam_policy():
    result = classify_change(_audit_event("SetIamPolicy"))
    assert result is not None
    assert result["change_type"] == "IAM_POLICY"

def test_audit_instance_stop():
    result = classify_change(_audit_event("v1.compute.instances.stop"))
    assert result is not None
    assert result["change_type"] == "status_change"

def test_audit_firewall_patch():
    result = classify_change(_audit_event("v1.compute.firewalls.patch"))
    assert result is not None
    assert result["change_type"] == "firewall_rule_change"

def test_audit_unknown_method_discarded():
    assert classify_change(_audit_event("v1.compute.instances.getSerialPortOutput")) is None


# ---------------------------------------------------------------------------
# Stage 2 — Affected remediation types
# ---------------------------------------------------------------------------

def test_iam_event_affects_iam_os_patch_misc():
    event = _iam_event(
        current_bindings=[("roles/editor", ["user:b@x.com"])],
        prior_bindings=[],
    )
    result = classify_change(event)
    assert {"IAM", "OS_PATCH", "MISCONFIGURATION"}.issubset(result["affected_remediation_types"])

def test_firewall_event_affects_firewall_and_misc():
    event = _resource_event(
        curr_data={"allowed": [{"IPProtocol": "all"}]},
        prior_data={"allowed": []},
        asset_type="compute.googleapis.com/Firewall",
    )
    result = classify_change(event)
    assert {"FIREWALL", "MISCONFIGURATION"}.issubset(result["affected_remediation_types"])


# ---------------------------------------------------------------------------
# Stage 3 — Proximity hops
# ---------------------------------------------------------------------------

def test_iam_event_uses_iam_proximity_hops():
    event = _iam_event(
        current_bindings=[("roles/owner", ["user:a@x.com"])],
        prior_bindings=[],
    )
    result = classify_change(event)
    assert result["proximity_hops"] == IAM_PROXIMITY_HOPS

def test_non_iam_event_uses_standard_hops():
    event = _resource_event(
        curr_data={"status": "STOPPED"},
        prior_data={"status": "RUNNING"},
    )
    result = classify_change(event)
    assert result["proximity_hops"] == PROXIMITY_HOPS


# ---------------------------------------------------------------------------
# Result structure
# ---------------------------------------------------------------------------

def test_result_contains_required_keys():
    event = _iam_event(
        current_bindings=[("roles/viewer", ["user:a@x.com"])],
        prior_bindings=[],
    )
    result = classify_change(event)
    required = {
        "change_type", "asset_name", "asset_type", "content_type",
        "affected_remediation_types", "proximity_hops",
        "prior_asset", "updated_asset", "raw_event",
    }
    assert required.issubset(result.keys())
