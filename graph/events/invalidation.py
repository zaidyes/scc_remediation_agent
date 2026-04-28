"""
Tiered invalidation response.

When a material change arrives and affects a pending approval, the response
is proportional — not every change invalidates the approval. Five levels:

  IGNORE      → no action
  ANNOTATE    → record on approval, no notification
  WARN        → notify approver, execution continues unless they object
  INVALIDATE  → void approval, trigger re-analysis
  HARD_BLOCK  → stop execution immediately, require human resolution
"""
import datetime
import os

from google.cloud import firestore, tasks_v2

from graph.events.proximity_index import deindex_approval

_RESPONSE_LEVELS = ("IGNORE", "ANNOTATE", "WARN", "INVALIDATE", "HARD_BLOCK")


def determine_response(change: dict, approval: dict) -> str:
    """
    Returns the appropriate invalidation response level for a change
    against a specific approval record.

    change:   classified change dict from filter.classify_change()
    approval: Firestore approval document dict
    """
    change_type = change["change_type"]
    status = approval.get("status", "PENDING")
    scheduled_at = approval.get("scheduled_execution_at")
    minutes_to_execution = _minutes_until(scheduled_at)

    # ------------------------------------------------------------------- #
    # Hard BLOCK conditions — always block regardless of timing
    # ------------------------------------------------------------------- #
    if change_type == "deletion":
        return "HARD_BLOCK"

    freeze_label = _is_freeze_label_added(change)
    if freeze_label:
        return "HARD_BLOCK"

    if change_type == "IAM_POLICY" and minutes_to_execution is not None and minutes_to_execution <= 60:
        return "HARD_BLOCK"

    if (
        change_type == "status_change"
        and status == "APPROVED"
        and minutes_to_execution is not None
        and minutes_to_execution <= 60
    ):
        return "HARD_BLOCK"

    if (
        change_type == "service_account_change"
        and status == "APPROVED"
        and minutes_to_execution is not None
        and minutes_to_execution <= 60
    ):
        return "HARD_BLOCK"

    # ------------------------------------------------------------------- #
    # Distant changes — always just annotate
    # ------------------------------------------------------------------- #
    if minutes_to_execution is None or minutes_to_execution > 24 * 60:
        return "ANNOTATE"

    # ------------------------------------------------------------------- #
    # INVALIDATE conditions
    # ------------------------------------------------------------------- #
    if change_type == "IAM_POLICY":
        return "INVALIDATE"

    if change_type == "status_change" and status == "APPROVED":
        return "INVALIDATE"

    if change_type == "status_change" and status == "PENDING":
        return "INVALIDATE"

    if change_type == "critical_label_change" and status == "PENDING":
        return "INVALIDATE"

    if change_type == "service_account_change" and status == "PENDING":
        return "INVALIDATE"

    # ------------------------------------------------------------------- #
    # WARN conditions
    # ------------------------------------------------------------------- #
    if change_type == "critical_label_change" and status == "APPROVED":
        return "WARN"

    if change_type == "firewall_rule_change" and minutes_to_execution > 60:
        return "ANNOTATE"

    # ------------------------------------------------------------------- #
    # Default — no action needed for this specific approval
    # ------------------------------------------------------------------- #
    return "IGNORE"


async def apply_response(
    response: str,
    change: dict,
    approval_id: str,
) -> None:
    """
    Applies the invalidation response to the approval Firestore document
    and triggers any side effects (notifications, re-analysis tasks).
    """
    if response == "IGNORE":
        return

    db = firestore.AsyncClient()
    approval_ref = db.collection("approvals").document(approval_id)

    if response == "ANNOTATE":
        await approval_ref.update({
            "change_annotations": firestore.ArrayUnion([{
                "change_type": change["change_type"],
                "asset": change["asset_name"],
                "recorded_at": datetime.datetime.utcnow().isoformat(),
                "reason": f"Non-blocking {change['change_type']} detected on {change['asset_name']}",
            }])
        })

    elif response == "WARN":
        await approval_ref.update({
            "warnings": firestore.ArrayUnion([
                f"{change['change_type']} on {change['asset_name']} at "
                f"{datetime.datetime.utcnow().isoformat()}"
            ])
        })
        # Notification to approver is handled by the approval card webhook —
        # the UI polls for warnings on open approvals.

    elif response == "INVALIDATE":
        approval_doc = await approval_ref.get()
        approval_data = approval_doc.to_dict() if approval_doc.exists else {}

        await approval_ref.update({
            "status": "INVALIDATED",
            "invalidation_reason": (
                f"{change['change_type']} on {change['asset_name']} "
                f"at {datetime.datetime.utcnow().isoformat()}"
            ),
            "invalidated_at": firestore.SERVER_TIMESTAMP,
        })

        # Remove from proximity index
        deindex_approval(
            approval_id=approval_id,
            target_asset=approval_data.get("asset_name", ""),
            blast_radius_assets=approval_data.get("blast_radius_assets", []),
        )

        # Enqueue re-analysis with a 2-minute delay to let related events settle
        task_id = await _enqueue_reanalysis(approval_id, approval_data)
        await approval_ref.update({"reanalysis_task_id": task_id})

        # Emit ON_INVALIDATION hook so the audit log and any custom hooks fire
        try:
            from app.hooks import fire, ON_INVALIDATION
            await fire(ON_INVALIDATION, {
                "event":              ON_INVALIDATION,
                "customer_id":        approval_data.get("customer_id", ""),
                "finding_id":         approval_data.get("finding_id", ""),
                "approval_id":        approval_id,
                "invalidation_reason": (
                    f"{change['change_type']} on {change['asset_name']}"
                ),
                "asset_name":         approval_data.get("asset_name", ""),
                "plan_id":            approval_data.get("plan_id"),
                "config":             None,
            })
        except Exception as _hook_exc:
            print(f"[invalidation] Hook fire failed: {_hook_exc}")

    elif response == "HARD_BLOCK":
        await approval_ref.update({
            "status": "BLOCKED",
            "block_reason": (
                f"Automatic block: {change['change_type']} on {change['asset_name']} "
                f"at {datetime.datetime.utcnow().isoformat()}"
            ),
            "blocked_at": firestore.SERVER_TIMESTAMP,
        })

        approval_doc = await approval_ref.get()
        if approval_doc.exists:
            data = approval_doc.to_dict()
            deindex_approval(
                approval_id=approval_id,
                target_asset=data.get("asset_name", ""),
                blast_radius_assets=data.get("blast_radius_assets", []),
            )


async def _enqueue_reanalysis(approval_id: str, approval_data: dict) -> str:
    """
    Enqueues a Cloud Tasks task to re-run the full analysis pipeline
    for the invalidated approval. 2-minute delay to allow event settling.
    """
    project = os.environ.get("GOOGLE_CLOUD_PROJECT", "")
    location = os.environ.get("CLOUD_TASKS_LOCATION", "us-central1")
    queue = os.environ.get("CLOUD_TASKS_QUEUE", "scc-remediation-tasks")
    scheduler_url = os.environ.get("SCHEDULER_SERVICE_URL", "")

    client = tasks_v2.CloudTasksAsyncClient()
    parent = f"projects/{project}/locations/{location}/queues/{queue}"

    import json
    payload = json.dumps({
        "action": "reanalyse",
        "finding_id": approval_data.get("finding_id"),
        "supersedes_approval_id": approval_id,
        "customer_id": approval_data.get("customer_id", ""),
    }).encode()

    task = tasks_v2.Task(
        http_request=tasks_v2.HttpRequest(
            http_method=tasks_v2.HttpMethod.POST,
            url=f"{scheduler_url}/internal/reanalyse",
            body=payload,
            headers={"Content-Type": "application/json"},
            oidc_token=tasks_v2.OidcToken(
                service_account_email=os.environ.get("AGENT_SA_EMAIL", "")
            ),
        ),
        schedule_time=_proto_timestamp_in(seconds=120),
    )

    created = await client.create_task(parent=parent, task=task)
    return created.name.split("/")[-1]


def _minutes_until(scheduled_at) -> float | None:
    """Returns minutes until scheduled_execution_at, or None if not scheduled."""
    if not scheduled_at:
        return None
    if hasattr(scheduled_at, "timestamp"):
        # Firestore Timestamp object
        dt = scheduled_at.astimezone(datetime.timezone.utc).replace(tzinfo=None)
    elif isinstance(scheduled_at, str):
        dt = datetime.datetime.fromisoformat(scheduled_at)
    else:
        return None
    delta = dt - datetime.datetime.utcnow()
    return delta.total_seconds() / 60


def _is_freeze_label_added(change: dict) -> bool:
    """Returns True if the change added a change-freeze=true label."""
    if change["change_type"] != "critical_label_change":
        return False
    updated = change.get("updated_asset", {})
    labels = updated.get("resource", {}).get("data", {}).get("labels", {})
    return labels.get("change-freeze") == "true"


def _proto_timestamp_in(seconds: int):
    from google.protobuf import timestamp_pb2
    import datetime
    ts = timestamp_pb2.Timestamp()
    ts.FromDatetime(datetime.datetime.utcnow() + datetime.timedelta(seconds=seconds))
    return ts
