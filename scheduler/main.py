"""
Webhook handler and Cloud Tasks worker for approval responses.

Deployed as a separate Cloud Run service. Receives:
  - POST /webhook/chat      — Google Chat interactive card button clicks
  - POST /webhook/pagerduty — PagerDuty webhook acknowledgments
  - POST /webhook/jira      — Jira issue transition webhooks
  - POST /internal/escalate — Cloud Tasks escalation jobs
  - POST /internal/execute  — Cloud Tasks remediation execution jobs
"""
import json
import os
import asyncio
import datetime
from fastapi import FastAPI, Request, HTTPException, Header
from google.cloud import firestore, tasks_v2

app = FastAPI()
_db = None


def _get_db() -> firestore.Client:
    global _db
    if _db is None:
        _db = firestore.Client()
    return _db


# ---------------------------------------------------------------------------
# Google Chat webhook
# ---------------------------------------------------------------------------

@app.post("/webhook/chat")
async def chat_webhook(request: Request):
    """
    Receives interactive card action callbacks from Google Chat.
    Validates the approver, updates Firestore, and enqueues execution or deferral.
    """
    body = await request.json()

    action_name = body.get("action", {}).get("actionMethodName", "")
    parameters = {
        p["key"]: p["value"]
        for p in body.get("action", {}).get("parameters", [])
    }
    approval_id = parameters.get("approval_id")
    responder_email = body.get("user", {}).get("email", "")

    if not approval_id:
        raise HTTPException(status_code=400, detail="Missing approval_id")

    db = _get_db()
    doc_ref = db.collection("approvals").document(approval_id)
    doc = doc_ref.get()

    if not doc.exists:
        raise HTTPException(status_code=404, detail="Approval not found")

    approval = doc.to_dict()

    if approval.get("status") != "PENDING":
        return _chat_already_actioned_response(approval)

    customer_id = os.environ.get("CUSTOMER_ID", "")
    config_doc = db.collection("configs").document(customer_id).get()
    if not config_doc.exists:
        raise HTTPException(status_code=500, detail="Customer config not found")

    from config.schema import CustomerConfig
    config = CustomerConfig(**config_doc.to_dict())

    if not _is_valid_approver(responder_email, approval["severity"], config):
        return {
            "text": f"You ({responder_email}) are not authorised to approve "
                    f"{approval['severity']} findings."
        }

    now = datetime.datetime.utcnow()

    if action_name == "approve_remediation":
        doc_ref.update({
            "status": "APPROVED",
            "responded_by": responder_email,
            "responded_at": now,
        })
        _enqueue_execution(approval_id, approval["plan"], config)
        return _chat_update_card(approval_id, "APPROVED", responder_email, now)

    elif action_name == "reject_remediation":
        doc_ref.update({
            "status": "REJECTED",
            "responded_by": responder_email,
            "responded_at": now,
        })
        return _chat_update_card(approval_id, "REJECTED", responder_email, now)

    elif action_name == "defer_remediation":
        from scheduler.windows import next_maintenance_window
        next_window = next_maintenance_window(config, approval["asset_name"])
        doc_ref.update({
            "status": "DEFERRED",
            "responded_by": responder_email,
            "responded_at": now,
            "deferred_until": next_window,
        })
        _enqueue_execution(approval_id, approval["plan"], config, scheduled_at=next_window)
        return _chat_update_card(
            approval_id, "DEFERRED", responder_email, now, deferred_until=next_window
        )

    raise HTTPException(status_code=400, detail=f"Unknown action: {action_name}")


# ---------------------------------------------------------------------------
# PagerDuty webhook
# ---------------------------------------------------------------------------

@app.post("/webhook/pagerduty")
async def pagerduty_webhook(request: Request):
    """Receives PagerDuty webhook events for acknowledgment and resolution."""
    body = await request.json()

    for event in body.get("messages", []):
        event_type = event.get("type", "")
        incident = event.get("incident", {})
        dedup_key = incident.get("dedup_key", "")  # maps to approval_id

        if not dedup_key:
            continue

        db = _get_db()
        doc_ref = db.collection("approvals").document(dedup_key)
        doc = doc_ref.get()
        if not doc.exists or doc.to_dict().get("status") != "PENDING":
            continue

        if event_type == "incident.acknowledge":
            doc_ref.update({"status": "APPROVED", "responded_at": datetime.datetime.utcnow()})
            approval = doc.to_dict()
            customer_id = os.environ.get("CUSTOMER_ID", "")
            config_doc = db.collection("configs").document(customer_id).get()
            if config_doc.exists:
                from config.schema import CustomerConfig
                config = CustomerConfig(**config_doc.to_dict())
                _enqueue_execution(dedup_key, approval["plan"], config)

        elif event_type == "incident.resolve":
            doc_ref.update({"status": "REJECTED", "responded_at": datetime.datetime.utcnow()})

    return {"status": "ok"}


# ---------------------------------------------------------------------------
# Jira webhook
# ---------------------------------------------------------------------------

@app.post("/webhook/jira")
async def jira_webhook(request: Request):
    """
    Receives Jira issue transition events.
    Maps issue comments APPROVED / REJECTED to approval decisions.
    """
    body = await request.json()

    issue = body.get("issue", {})
    comment_body = body.get("comment", {}).get("body", "").strip().upper()
    author_email = body.get("comment", {}).get("author", {}).get("emailAddress", "")

    labels = issue.get("fields", {}).get("labels", [])
    approval_id = next(
        (l.replace("approval-", "") for l in labels if l.startswith("approval-")), None
    )
    if not approval_id:
        return {"status": "ignored"}

    db = _get_db()
    doc_ref = db.collection("approvals").document(approval_id)
    doc = doc_ref.get()
    if not doc.exists or doc.to_dict().get("status") != "PENDING":
        return {"status": "already_actioned"}

    now = datetime.datetime.utcnow()

    if "APPROVED" in comment_body:
        doc_ref.update({"status": "APPROVED", "responded_by": author_email, "responded_at": now})
        approval = doc.to_dict()
        customer_id = os.environ.get("CUSTOMER_ID", "")
        config_doc = db.collection("configs").document(customer_id).get()
        if config_doc.exists:
            from config.schema import CustomerConfig
            config = CustomerConfig(**config_doc.to_dict())
            _enqueue_execution(approval_id, approval["plan"], config)

    elif "REJECTED" in comment_body:
        doc_ref.update({"status": "REJECTED", "responded_by": author_email, "responded_at": now})

    return {"status": "ok"}


# ---------------------------------------------------------------------------
# Internal Cloud Tasks endpoints
# ---------------------------------------------------------------------------

@app.post("/internal/escalate")
async def escalate(request: Request):
    """
    Called by Cloud Tasks when an approval times out without a response.
    Escalates to fallback approvers.
    """
    body = await request.json()
    approval_id = body.get("approval_id")
    if not approval_id:
        raise HTTPException(status_code=400, detail="Missing approval_id")

    db = _get_db()
    doc = db.collection("approvals").document(approval_id).get()
    if not doc.exists or doc.to_dict().get("status") != "PENDING":
        return {"status": "no_action_needed"}

    approval = doc.to_dict()
    customer_id = os.environ.get("CUSTOMER_ID", "")
    config_doc = db.collection("configs").document(customer_id).get()
    if not config_doc.exists:
        return {"status": "config_not_found"}

    from config.schema import CustomerConfig
    config = CustomerConfig(**config_doc.to_dict())

    fallback_approvers = [
        a for a in config.approval_policy.approvers
        if a.fallback_address and approval["severity"] in a.severity_levels
    ]
    if not fallback_approvers:
        print(f"[escalate] No fallback approvers for {approval_id}")
        return {"status": "no_fallback"}

    print(f"[escalate] Escalating approval {approval_id} to {len(fallback_approvers)} fallback approvers")
    db.collection("approvals").document(approval_id).update({
        "escalated_at": datetime.datetime.utcnow(),
        "escalation_count": firestore.Increment(1),
    })

    return {"status": "escalated"}


@app.post("/internal/execute")
async def execute(request: Request):
    """
    Called by Cloud Tasks to execute an approved remediation plan.
    Loads config, runs the plan, verifies closure.
    """
    body = await request.json()
    approval_id = body.get("approval_id")
    plan = body.get("plan")

    if not approval_id or not plan:
        raise HTTPException(status_code=400, detail="Missing approval_id or plan")

    customer_id = os.environ.get("CUSTOMER_ID", "")
    db = _get_db()
    config_doc = db.collection("configs").document(customer_id).get()
    if not config_doc.exists:
        raise HTTPException(status_code=500, detail="Config not found")

    from config.schema import CustomerConfig
    from app.main import _execute_plan

    config = CustomerConfig(**config_doc.to_dict())
    finding_id = plan.get("finding_id", "")
    finding = {"finding_id": finding_id, "resource_name": plan.get("asset_name", "")}

    await _execute_plan(plan, finding, config)
    return {"status": "executed"}


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _is_valid_approver(email: str, severity: str, config) -> bool:
    for approver in config.approval_policy.approvers:
        if severity in approver.severity_levels:
            if approver.address == email or approver.fallback_address == email:
                return True
    return False


def _enqueue_execution(
    approval_id: str,
    plan: dict,
    config,
    scheduled_at: datetime.datetime | None = None,
) -> None:
    project_id = os.environ.get("GOOGLE_CLOUD_PROJECT", "")
    webhook_url = os.environ.get("WEBHOOK_URL", "")
    if not project_id or not webhook_url:
        return

    client = tasks_v2.CloudTasksClient()
    queue = client.queue_path(project_id, "us-central1", "remediation-execution")

    task = {
        "http_request": {
            "http_method": tasks_v2.HttpMethod.POST,
            "url": f"{webhook_url}/internal/execute",
            "headers": {"Content-Type": "application/json"},
            "body": json.dumps({"approval_id": approval_id, "plan": plan}).encode(),
        },
    }
    if scheduled_at:
        task["schedule_time"] = scheduled_at

    try:
        client.create_task(request={"parent": queue, "task": task})
        print(f"[tasks] Enqueued execution for approval {approval_id}")
    except Exception as e:
        print(f"[tasks] Failed to enqueue execution: {e}")


def _chat_update_card(
    approval_id: str,
    status: str,
    responder: str,
    responded_at: datetime.datetime,
    deferred_until: datetime.datetime | None = None,
) -> dict:
    """Returns a Chat response that updates the card to reflect the decision."""
    status_text = {
        "APPROVED": f"Approved by {responder} at {responded_at.strftime('%H:%M UTC')}",
        "REJECTED": f"Rejected by {responder} at {responded_at.strftime('%H:%M UTC')}",
        "DEFERRED": f"Deferred by {responder} — scheduled for {deferred_until.strftime('%Y-%m-%d %H:%M UTC') if deferred_until else 'next window'}",
    }.get(status, status)

    return {
        "actionResponse": {"type": "UPDATE_MESSAGE"},
        "cardsV2": [{
            "cardId": f"approval-{approval_id}",
            "card": {
                "header": {"title": f"Remediation {status.lower()}", "subtitle": status_text},
                "sections": [{"widgets": [{"textParagraph": {"text": status_text}}]}],
            }
        }]
    }


def _chat_already_actioned_response(approval: dict) -> dict:
    status = approval.get("status", "unknown")
    by = approval.get("responded_by", "someone")
    return {"text": f"This approval has already been {status.lower()} by {by}."}
