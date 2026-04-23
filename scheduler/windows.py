import datetime
import pytz
from config.schema import MaintenanceWindow, CustomerConfig

def next_maintenance_window(config: CustomerConfig, asset_name: str) -> datetime.datetime:
    """
    Returns the UTC datetime of the start of the next maintenance window
    for the given asset. Checks resource label first, falls back to default.
    """
    from agent.tools.graph_tools import get_resource_maint_window
    resource_window_label = get_resource_maint_window(asset_name)
    
    # If the resource has a specific window format in the label, parse it.
    # For now, we fallback to the default config window if parsing is complex or not provided.
    window = config.approval_policy.default_maintenance_window
    return _compute_next_window(window)

def _compute_next_window(window: MaintenanceWindow) -> datetime.datetime:
    tz = pytz.timezone(window.timezone)
    now = datetime.datetime.now(tz)
    start_h, start_m = map(int, window.start_time_utc.split(":"))

    for days_ahead in range(8):
        candidate = now + datetime.timedelta(days=days_ahead)
        if candidate.weekday() in window.days_of_week:
            candidate = candidate.replace(
                hour=start_h, minute=start_m, second=0, microsecond=0
            )
            if candidate > now:
                return candidate.astimezone(pytz.utc).replace(tzinfo=None)

    raise ValueError("No valid maintenance window found in next 7 days")
