"""
Unit tests for graph/events/invalidation.py — determine_response().

determine_response() is a pure function; no Firestore or Cloud Tasks calls.
apply_response() requires GCP clients and is not tested here.
"""
import datetime
import pytest
from graph.events.invalidation import determine_response


def _approval(status="PENDING", minutes_from_now=None):
    approval = {"status": status}
    if minutes_from_now is not None:
        future = datetime.datetime.utcnow() + datetime.timedelta(minutes=minutes_from_now)
        approval["scheduled_execution_at"] = future.isoformat()
    return approval


def _change(change_type, updated_labels=None):
    change = {
        "change_type": change_type,
        "asset_name": "//compute.googleapis.com/projects/p/instances/vm1",
        "updated_asset": {},
    }
    if updated_labels is not None:
        change["updated_asset"] = {"resource": {"data": {"labels": updated_labels}}}
    return change


# ---------------------------------------------------------------------------
# HARD_BLOCK conditions — always block regardless of timing
# ---------------------------------------------------------------------------

def test_deletion_always_hard_blocks():
    assert determine_response(_change("deletion"), _approval(minutes_from_now=120)) == "HARD_BLOCK"

def test_deletion_hard_blocks_even_distant():
    assert determine_response(_change("deletion"), _approval(minutes_from_now=2000)) == "HARD_BLOCK"

def test_freeze_label_added_hard_blocks():
    change = _change("critical_label_change", updated_labels={"change-freeze": "true"})
    assert determine_response(change, _approval(minutes_from_now=120)) == "HARD_BLOCK"

def test_iam_change_within_60min_hard_blocks():
    assert determine_response(_change("IAM_POLICY"), _approval(minutes_from_now=30)) == "HARD_BLOCK"

def test_status_change_approved_within_60min_hard_blocks():
    assert determine_response(
        _change("status_change"),
        _approval(status="APPROVED", minutes_from_now=30),
    ) == "HARD_BLOCK"

def test_service_account_change_approved_within_60min_hard_blocks():
    assert determine_response(
        _change("service_account_change"),
        _approval(status="APPROVED", minutes_from_now=45),
    ) == "HARD_BLOCK"


# ---------------------------------------------------------------------------
# ANNOTATE — distant changes (>24h away or no schedule)
# ---------------------------------------------------------------------------

def test_iam_change_no_schedule_annotates():
    # No scheduled_execution_at → minutes_to_execution is None → ANNOTATE
    assert determine_response(_change("IAM_POLICY"), _approval()) == "ANNOTATE"

def test_any_change_beyond_24h_annotates():
    assert determine_response(
        _change("status_change"),
        _approval(minutes_from_now=25 * 60),
    ) == "ANNOTATE"

def test_firewall_change_no_schedule_annotates():
    assert determine_response(_change("firewall_rule_change"), _approval()) == "ANNOTATE"


# ---------------------------------------------------------------------------
# INVALIDATE conditions
# ---------------------------------------------------------------------------

def test_iam_change_outside_60min_invalidates():
    # < 24h but > 60min
    assert determine_response(
        _change("IAM_POLICY"),
        _approval(status="PENDING", minutes_from_now=120),
    ) == "INVALIDATE"

def test_status_change_on_approved_invalidates():
    assert determine_response(
        _change("status_change"),
        _approval(status="APPROVED", minutes_from_now=120),
    ) == "INVALIDATE"

def test_status_change_on_pending_invalidates():
    assert determine_response(
        _change("status_change"),
        _approval(status="PENDING", minutes_from_now=120),
    ) == "INVALIDATE"

def test_critical_label_change_on_pending_invalidates():
    # Non-freeze label change (no change-freeze=true) on PENDING
    change = _change("critical_label_change", updated_labels={"env": "prod"})
    assert determine_response(change, _approval(status="PENDING", minutes_from_now=120)) == "INVALIDATE"

def test_service_account_change_on_pending_invalidates():
    assert determine_response(
        _change("service_account_change"),
        _approval(status="PENDING", minutes_from_now=120),
    ) == "INVALIDATE"


# ---------------------------------------------------------------------------
# WARN conditions
# ---------------------------------------------------------------------------

def test_critical_label_change_on_approved_warns():
    change = _change("critical_label_change", updated_labels={"env": "prod"})
    assert determine_response(change, _approval(status="APPROVED", minutes_from_now=120)) == "WARN"


# ---------------------------------------------------------------------------
# ANNOTATE — firewall rule change outside 60 min
# ---------------------------------------------------------------------------

def test_firewall_change_beyond_60min_annotates():
    assert determine_response(
        _change("firewall_rule_change"),
        _approval(status="PENDING", minutes_from_now=120),
    ) == "ANNOTATE"


# ---------------------------------------------------------------------------
# IGNORE — default fallback
# ---------------------------------------------------------------------------

def test_unknown_change_type_falls_through_to_ignore():
    # A change type that hits none of the explicit conditions
    # and is not a deletion or freeze — should fall through to IGNORE
    change = _change("network_interface_change")
    result = determine_response(change, _approval(status="PENDING", minutes_from_now=120))
    assert result == "IGNORE"


# ---------------------------------------------------------------------------
# Boundary conditions around the 60-minute threshold
# ---------------------------------------------------------------------------

def test_exactly_60min_iam_hard_blocks():
    assert determine_response(
        _change("IAM_POLICY"),
        _approval(minutes_from_now=60),
    ) == "HARD_BLOCK"

def test_61min_iam_invalidates_not_hard_blocks():
    assert determine_response(
        _change("IAM_POLICY"),
        _approval(minutes_from_now=61),
    ) == "INVALIDATE"


# ---------------------------------------------------------------------------
# _is_freeze_label_added edge cases
# ---------------------------------------------------------------------------

def test_freeze_label_false_value_does_not_hard_block():
    change = _change("critical_label_change", updated_labels={"change-freeze": "false"})
    # change-freeze=false is not a freeze — should not hard block
    result = determine_response(change, _approval(minutes_from_now=120))
    assert result != "HARD_BLOCK"

def test_non_critical_label_change_type_does_not_trigger_freeze_check():
    change = _change("status_change", updated_labels={"change-freeze": "true"})
    # status_change type — freeze label check only runs for critical_label_change
    result = determine_response(change, _approval(minutes_from_now=120))
    assert result != "HARD_BLOCK"  # status_change 120min out → INVALIDATE
