import datetime
import pytest
import pytz
from unittest.mock import patch

from scheduler.windows import _compute_next_window
from scheduler.freeze import is_change_frozen
from config.schema import MaintenanceWindow


# ---------------------------------------------------------------------------
# Maintenance window computation
# ---------------------------------------------------------------------------

def _window(days, start="02:00", end="05:00", tz="UTC"):
    return MaintenanceWindow(
        days_of_week=days,
        start_time_utc=start,
        end_time_utc=end,
        timezone=tz,
    )


def test_next_window_same_day_in_future():
    """If today is a window day and the window hasn't started yet, return today."""
    window = _window(days=[0, 1, 2, 3, 4, 5, 6], start="23:00")  # every day at 23:00
    tz = pytz.timezone("UTC")
    # Pin 'now' to 12:00 UTC on a Monday (weekday 0)
    fixed_now = datetime.datetime(2026, 4, 27, 12, 0, 0, tzinfo=tz)  # Monday

    with patch("scheduler.windows.datetime") as mock_dt:
        mock_dt.datetime.now.return_value = fixed_now
        mock_dt.timedelta = datetime.timedelta
        result = _compute_next_window(window)

    assert result.hour == 23
    assert result.minute == 0


def test_next_window_skips_past_time_today():
    """If today is a window day but the window has passed, find the next occurrence."""
    window = _window(days=[0], start="02:00")  # Mondays only at 02:00
    tz = pytz.timezone("UTC")
    fixed_now = datetime.datetime(2026, 4, 27, 10, 0, 0, tzinfo=tz)  # Monday at 10:00 — already past

    with patch("scheduler.windows.datetime") as mock_dt:
        mock_dt.datetime.now.return_value = fixed_now
        mock_dt.timedelta = datetime.timedelta
        result = _compute_next_window(window)

    # Should roll to next Monday
    assert result.weekday() == 0
    assert result > fixed_now.replace(tzinfo=None)


def test_next_window_timezone_conversion():
    """Result is always returned as naive UTC."""
    window = _window(days=[0, 1, 2, 3, 4, 5, 6], start="00:00", tz="America/New_York")
    tz = pytz.timezone("America/New_York")
    fixed_now = datetime.datetime(2026, 4, 27, 10, 0, 0, tzinfo=tz)

    with patch("scheduler.windows.datetime") as mock_dt:
        mock_dt.datetime.now.return_value = fixed_now
        mock_dt.timedelta = datetime.timedelta
        result = _compute_next_window(window)

    assert result.tzinfo is None  # naive UTC


def test_next_window_no_valid_window_raises():
    """If no window day falls within 7 days (impossible in practice but let's be safe)."""
    window = _window(days=[])  # no valid days
    tz = pytz.timezone("UTC")
    fixed_now = datetime.datetime(2026, 4, 27, 12, 0, 0, tzinfo=tz)

    with patch("scheduler.windows.datetime") as mock_dt:
        mock_dt.datetime.now.return_value = fixed_now
        mock_dt.timedelta = datetime.timedelta
        with pytest.raises(ValueError, match="No valid maintenance window"):
            _compute_next_window(window)


# ---------------------------------------------------------------------------
# Change freeze detection
# ---------------------------------------------------------------------------

def test_freeze_resource_label():
    with patch("scheduler.freeze.get_resource_labels", return_value={"change-freeze": "true"}), \
         patch("scheduler.freeze._get_project_resource", return_value=""):
        assert is_change_frozen("//compute.googleapis.com/projects/p/instances/vm1", None)


def test_freeze_project_label():
    with patch("scheduler.freeze.get_resource_labels", side_effect=[
        {},  # resource labels — no freeze
        {"change-freeze": "true"},  # project labels — freeze!
    ]), patch("scheduler.freeze._get_project_resource", return_value="//cloudresourcemanager.googleapis.com/projects/p"):
        assert is_change_frozen("//compute.googleapis.com/projects/p/instances/vm1", None)


def test_no_freeze():
    with patch("scheduler.freeze.get_resource_labels", return_value={"env": "prod"}), \
         patch("scheduler.freeze._get_project_resource", return_value="//cloudresourcemanager.googleapis.com/projects/p"):
        assert not is_change_frozen("//compute.googleapis.com/projects/p/instances/vm1", None)


def test_freeze_false_value_is_not_frozen():
    with patch("scheduler.freeze.get_resource_labels", return_value={"change-freeze": "false"}), \
         patch("scheduler.freeze._get_project_resource", return_value=""):
        assert not is_change_frozen("//compute.googleapis.com/projects/p/instances/vm1", None)
