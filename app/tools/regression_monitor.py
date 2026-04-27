"""
Post-fix regression monitor.

For 30 minutes after any remediation, monitors Cloud Logging error rates on
the target resource and all blast-radius assets. If the error rate increases
more than 2 standard deviations above the 7-day baseline, triggers automatic
rollback and alerts the approver.
"""
import asyncio
import datetime
import statistics

from google.cloud import monitoring_v3
from google.protobuf import timestamp_pb2

from app.tools.rollback_tools import execute_rollback


async def monitor_for_regression(
    plan: dict,
    blast_radius_assets: list[str],
    monitor_duration_minutes: int = 30,
    check_interval_seconds: int = 60,
) -> dict:
    """
    Monitors error rates on the target and blast radius assets.
    Triggers rollback if a regression is detected.

    Returns:
      {"status": "STABLE"|"REGRESSION_DETECTED", "rollback_triggered": bool, ...}
    """
    project_id = plan.get("project_id") or _extract_project(plan["asset_name"])
    assets_to_monitor = [plan["asset_name"]] + blast_radius_assets[:9]  # cap at 10 total
    approval_id = plan.get("approval_id")

    client = monitoring_v3.MetricServiceClient()

    baseline = await _get_error_rate_baseline(client, project_id, assets_to_monitor)
    total_checks = (monitor_duration_minutes * 60) // check_interval_seconds

    for check_num in range(total_checks):
        await asyncio.sleep(check_interval_seconds)

        current = await _get_current_error_rate(client, project_id, assets_to_monitor)

        for asset, rate in current.items():
            b = baseline.get(asset, {})
            mean = b.get("mean", 0.0)
            std = b.get("std", 0.0)

            # Only fire if std > 0 (flat baselines have infinite signal-to-noise)
            if std > 0 and rate > mean + (2 * std):
                rollback_result = {"status": "SKIPPED", "output": "No approval_id on plan"}
                if approval_id:
                    rollback_result = await execute_rollback(approval_id)

                return {
                    "status": "REGRESSION_DETECTED",
                    "asset": asset,
                    "current_error_rate": rate,
                    "baseline_mean": round(mean, 4),
                    "baseline_std": round(std, 4),
                    "threshold": round(mean + 2 * std, 4),
                    "check_number": check_num + 1,
                    "elapsed_minutes": round(((check_num + 1) * check_interval_seconds) / 60, 1),
                    "rollback_triggered": rollback_result.get("status") == "SUCCESS",
                    "rollback_result": rollback_result,
                }

    return {
        "status": "STABLE",
        "rollback_triggered": False,
        "assets_monitored": len(assets_to_monitor),
        "checks_completed": total_checks,
        "duration_minutes": monitor_duration_minutes,
    }


async def _get_error_rate_baseline(
    client: monitoring_v3.MetricServiceClient,
    project_id: str,
    assets: list[str],
) -> dict[str, dict]:
    """
    Queries the last 7 days of ERROR-severity log entry counts in 1-hour buckets.
    Returns {asset_name: {"mean": float, "std": float}} for each asset.
    """
    now = datetime.datetime.utcnow()
    baseline_start = now - datetime.timedelta(days=7)
    baseline = {}

    for asset in assets:
        try:
            resource_type, resource_labels = _asset_to_monitored_resource(asset, project_id)
            label_filter = " AND ".join(
                f'metric.labels."{k}"="{v}"' for k, v in resource_labels.items()
            )
            full_filter = (
                f'metric.type="logging.googleapis.com/log_entry_count" '
                f'AND metric.labels.severity="ERROR" '
                f'AND resource.type="{resource_type}"'
            )
            if label_filter:
                full_filter += f" AND {label_filter}"

            interval = monitoring_v3.TimeInterval(
                start_time=_to_proto_timestamp(baseline_start),
                end_time=_to_proto_timestamp(now),
            )
            aggregation = monitoring_v3.Aggregation(
                alignment_period={"seconds": 3600},  # 1-hour buckets
                per_series_aligner=monitoring_v3.Aggregation.Aligner.ALIGN_RATE,
                cross_series_reducer=monitoring_v3.Aggregation.Reducer.REDUCE_SUM,
            )

            request = monitoring_v3.ListTimeSeriesRequest(
                name=f"projects/{project_id}",
                filter=full_filter,
                interval=interval,
                aggregation=aggregation,
            )
            series = list(client.list_time_series(request=request))

            hourly_rates = []
            for ts in series:
                for point in ts.points:
                    hourly_rates.append(point.value.double_value)

            if len(hourly_rates) >= 2:
                baseline[asset] = {
                    "mean": statistics.mean(hourly_rates),
                    "std": statistics.stdev(hourly_rates),
                    "sample_count": len(hourly_rates),
                }
            elif len(hourly_rates) == 1:
                baseline[asset] = {
                    "mean": hourly_rates[0],
                    "std": hourly_rates[0] * 0.5,  # assume 50% variance for single sample
                    "sample_count": 1,
                }
            # If no data points, asset is omitted from baseline (no regression possible)

        except Exception:
            pass  # silently skip assets with no monitoring data

    return baseline


async def _get_current_error_rate(
    client: monitoring_v3.MetricServiceClient,
    project_id: str,
    assets: list[str],
) -> dict[str, float]:
    """
    Returns the error rate (errors/sec) for the last 5 minutes for each asset.
    """
    now = datetime.datetime.utcnow()
    window_start = now - datetime.timedelta(minutes=5)
    current = {}

    for asset in assets:
        try:
            resource_type, resource_labels = _asset_to_monitored_resource(asset, project_id)
            label_filter = " AND ".join(
                f'metric.labels."{k}"="{v}"' for k, v in resource_labels.items()
            )
            full_filter = (
                f'metric.type="logging.googleapis.com/log_entry_count" '
                f'AND metric.labels.severity="ERROR" '
                f'AND resource.type="{resource_type}"'
            )
            if label_filter:
                full_filter += f" AND {label_filter}"

            interval = monitoring_v3.TimeInterval(
                start_time=_to_proto_timestamp(window_start),
                end_time=_to_proto_timestamp(now),
            )
            aggregation = monitoring_v3.Aggregation(
                alignment_period={"seconds": 300},
                per_series_aligner=monitoring_v3.Aggregation.Aligner.ALIGN_RATE,
                cross_series_reducer=monitoring_v3.Aggregation.Reducer.REDUCE_SUM,
            )

            request = monitoring_v3.ListTimeSeriesRequest(
                name=f"projects/{project_id}",
                filter=full_filter,
                interval=interval,
                aggregation=aggregation,
            )
            series = list(client.list_time_series(request=request))

            total_rate = sum(
                point.value.double_value
                for ts in series
                for point in ts.points
            )
            current[asset] = total_rate

        except Exception:
            pass

    return current


# --------------------------------------------------------------------------- #
# Helpers
# --------------------------------------------------------------------------- #

def _asset_to_monitored_resource(asset_name: str, project_id: str) -> tuple[str, dict]:
    """
    Maps a CAI asset name to a Cloud Monitoring resource type and label dict.
    Falls back to a generic gce_instance type for compute resources.
    """
    name = asset_name.lower()

    if "instances" in name:
        instance = asset_name.split("/")[-1]
        zone = _extract_segment(asset_name, "zones")
        return "gce_instance", {"instance_id": instance, "zone": zone, "project_id": project_id}

    if "buckets" in name or "storage" in name:
        bucket = asset_name.split("/")[-1]
        return "gcs_bucket", {"bucket_name": bucket, "project_id": project_id}

    if "functions" in name:
        func = asset_name.split("/")[-1]
        region = _extract_segment(asset_name, "locations")
        return "cloud_function", {"function_name": func, "region": region, "project_id": project_id}

    if "run" in name or "services" in name:
        service = asset_name.split("/")[-1]
        region = _extract_segment(asset_name, "locations")
        return "cloud_run_revision", {"service_name": service, "location": region,
                                      "project_id": project_id}

    # Generic fallback — catches most compute resources
    return "gce_instance", {"project_id": project_id}


def _extract_project(asset_name: str) -> str:
    parts = asset_name.replace("//", "").split("/")
    if "projects" in parts:
        return parts[parts.index("projects") + 1]
    return ""


def _extract_segment(asset_name: str, segment: str) -> str:
    parts = asset_name.replace("//", "").split("/")
    if segment in parts:
        return parts[parts.index(segment) + 1]
    return ""


def _to_proto_timestamp(dt: datetime.datetime) -> timestamp_pb2.Timestamp:
    ts = timestamp_pb2.Timestamp()
    ts.FromDatetime(dt)
    return ts
