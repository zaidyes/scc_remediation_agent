import uuid
import datetime
import json
from typing import Any
import aiohttp
from google.cloud import firestore, tasks_v2
from googleapiclient.discovery import build


async def dispatch_approval_request(
    plan: Any,
    finding: Any,
    impact: Any,
    config: Any,
    channels: list[str],
    tier: int = 3,
) -> str:
    """
    Creates an approval record in Firestore and sends the card to all channels.
    Returns the approval_id.

    tier: execution tier (1=autonomous [not dispatched], 2=single-tap, 3=expert review)
    """
    approval_id = str(uuid.uuid4())
    db = firestore.Client()

    # Tier 2 timeout is 4 hours before escalating to Tier 3 (per addendum §2.2)
    expires_at = (
        datetime.datetime.utcnow() + datetime.timedelta(hours=4)
        if tier == 2
        else _compute_expiry(finding["severity"], config)
    )

    approval_doc = {
        "approval_id": approval_id,
        "plan_id": plan["plan_id"],
        "finding_id": finding["finding_id"],
        "asset_name": finding["resource_name"],
        "severity": finding["severity"],
        "blast_level": impact.get("blast_level", "UNKNOWN"),
        "confidence_score": plan.get("confidence_score"),
        "execution_tier": tier,
        "status": "PENDING",
        "created_at": firestore.SERVER_TIMESTAMP,
        "expires_at": expires_at,
        "channels_notified": channels,
        "plan_summary": plan["summary"],
        "rollback_steps": plan.get("rollback_steps", []),
        "plan": plan,
        "responded_by": None,
        "responded_at": None,
        # Fields required by addendum §6.4 (populated by later phases)
        "blast_radius_assets": impact.get("blast_radius_assets", []),
        "scheduled_execution_at": None,
        "change_annotations": [],
        "warnings": [],
        "invalidation_reason": None,
        "invalidated_at": None,
        "block_reason": None,
        "blocked_at": None,
        "reanalysis_task_id": None,
        "supersedes_approval_id": None,
    }

    db.collection("approvals").document(approval_id).set(approval_doc)

    # Register in proximity index so the event processor can find this approval
    # when assets in its blast radius change.
    try:
        from graph.events.proximity_index import index_approval
        index_approval(
            approval_id=approval_id,
            target_asset=finding["resource_name"],
            blast_radius_assets=impact.get("blast_radius_assets", []),
        )
    except Exception as e:
        print(f"[proximity] Failed to index approval {approval_id}: {e}")

    for channel in channels:
        if channel == "google_chat" and config.notifications.google_chat_space:
            await _send_chat_card(approval_id, plan, finding, impact, config)
        if channel == "pagerduty" and config.notifications.pagerduty_service_key:
            await _send_pagerduty_alert(approval_id, plan, finding, impact, config)
        if channel == "jira" and config.notifications.jira_project_key:
            await _create_jira_ticket(approval_id, plan, finding, impact, config)

    _schedule_escalation(approval_id, config)

    return approval_id


def _compute_expiry(severity: str, config) -> datetime.datetime:
    """Returns the UTC datetime at which this approval request expires."""
    grace_minutes = 30  # default
    for tier in config.approval_policy.tiers:
        tier_severities = tier.condition.get("severity", [])
        if severity in tier_severities:
            grace_minutes = tier.grace_period_minutes
            break
    return datetime.datetime.utcnow() + datetime.timedelta(minutes=grace_minutes)


def _schedule_escalation(approval_id: str, config) -> None:
    """Enqueues a Cloud Tasks job to escalate if no response by escalate_after_minutes."""
    import os
    project_id = os.environ.get("GOOGLE_CLOUD_PROJECT", "")
    if not project_id:
        return

    escalate_minutes = 15
    for tier in config.approval_policy.tiers:
        if tier.requires_approval:
            escalate_minutes = tier.escalate_after_minutes
            break

    client = tasks_v2.CloudTasksClient()
    queue = client.queue_path(project_id, "us-central1", "approval-escalations")
    webhook_url = os.environ.get("WEBHOOK_URL", "")

    schedule_time = datetime.datetime.utcnow() + datetime.timedelta(minutes=escalate_minutes)

    task = {
        "http_request": {
            "http_method": tasks_v2.HttpMethod.POST,
            "url": f"{webhook_url}/internal/escalate",
            "headers": {"Content-Type": "application/json"},
            "body": json.dumps({"approval_id": approval_id}).encode(),
        },
        "schedule_time": schedule_time,
    }

    try:
        client.create_task(request={"parent": queue, "task": task})
    except Exception as e:
        print(f"[escalation] Failed to schedule escalation for {approval_id}: {e}")


async def _send_chat_card(approval_id, plan, finding, impact, config):
    """Sends a structured Google Chat card with approve/reject/defer buttons."""
    service = build("chat", "v1")

    severity_color = {
        "CRITICAL": "#E24B4A",
        "HIGH": "#BA7517",
        "MEDIUM": "#378ADD",
        "LOW": "#639922",
    }.get(finding["severity"], "#888780")

    expiry = _compute_expiry(finding["severity"], config)
    rollback_text = "\n".join(
        f"{s['order']}. {s['action']}"
        for s in plan.get("rollback_steps", [])[:3]
    )

    # Pre-flight summary for the card
    preflight_results = plan.get("preflight_results", [])
    preflight_lines = [
        f"{'✅' if r['result'] == 'PASS' else '⚠️' if r['result'] == 'WARN' else '🚫'} "
        f"{r['check']}: {r['detail']}"
        for r in preflight_results
    ]
    preflight_text = "\n".join(preflight_lines) or "No pre-flight checks recorded."

    confidence = plan.get("confidence_score")
    confidence_text = f"{confidence:.0%}" if confidence is not None else "N/A"
    tier = plan.get("execution_tier", 3)
    tier_labels = {1: "Tier 1 — Autonomous", 2: "Tier 2 — Policy-assisted", 3: "Tier 3 — Expert review"}

    card = {
        "cardsV2": [{
            "cardId": f"approval-{approval_id}",
            "card": {
                "header": {
                    "title": "Remediation approval required",
                    "subtitle": f"{finding['severity']} · {finding['category']} · {tier_labels.get(tier, '')}",
                },
                "sections": [
                    {
                        "widgets": [
                            {"textParagraph": {"text": f"<b>Asset:</b> {finding['resource_name']}"}},
                            {"textParagraph": {"text": f"<b>Finding:</b> {plan['summary']}"}},
                            {"textParagraph": {"text": f"<b>Blast radius:</b> {impact.get('blast_level', 'UNKNOWN')} · {impact.get('prod_blast_count', 0)} prod dependencies"}},
                            {"textParagraph": {"text": f"<b>Confidence:</b> {confidence_text}"}},
                            {"textParagraph": {"text": f"<b>Risk assessment:</b> {plan.get('risk_assessment', '')}"}},
                            {"textParagraph": {"text": f"<b>Downtime:</b> {plan.get('estimated_downtime_minutes', 0)} min · Reboot: {'Yes' if plan.get('requires_reboot') else 'No'}"}},
                        ]
                    },
                    {
                        "header": "Pre-flight checks",
                        "widgets": [
                            {"textParagraph": {"text": preflight_text}}
                        ]
                    },
                    {
                        "header": "Rollback plan",
                        "widgets": [
                            {"textParagraph": {"text": rollback_text or "No rollback steps specified."}}
                        ]
                    },
                    {
                        "widgets": [{
                            "buttonList": {
                                "buttons": [
                                    {
                                        "text": "Approve",
                                        "color": {"red": 0.2, "green": 0.65, "blue": 0.32},
                                        "onClick": {"action": {
                                            "function": "approve_remediation",
                                            "parameters": [{"key": "approval_id", "value": approval_id}],
                                        }},
                                    },
                                    {
                                        "text": "Reject",
                                        "color": {"red": 0.89, "green": 0.29, "blue": 0.29},
                                        "onClick": {"action": {
                                            "function": "reject_remediation",
                                            "parameters": [{"key": "approval_id", "value": approval_id}],
                                        }},
                                    },
                                    {
                                        "text": "Defer to window",
                                        "onClick": {"action": {
                                            "function": "defer_remediation",
                                            "parameters": [{"key": "approval_id", "value": approval_id}],
                                        }},
                                    },
                                ]
                            }
                        }],
                    },
                    {
                        "widgets": [
                            {"textParagraph": {"text": f"<font color='#888780'>Approval ID: {approval_id} · Expires: {expiry.strftime('%Y-%m-%d %H:%M UTC')}</font>"}},
                        ]
                    },
                ],
            }
        }]
    }

    try:
        service.spaces().messages().create(
            parent=config.notifications.google_chat_space,
            body=card,
        ).execute()
    except Exception as e:
        print(f"[chat] Failed to send card: {e}")


async def _send_pagerduty_alert(approval_id, plan, finding, impact, config):
    """Triggers a PagerDuty incident via Events API v2."""
    payload = {
        "routing_key": config.notifications.pagerduty_service_key,
        "event_action": "trigger",
        "dedup_key": approval_id,
        "payload": {
            "summary": f"[SCC Remediation] {finding['severity']} · {finding['category']} on {finding['resource_name']}",
            "severity": finding["severity"].lower(),
            "source": "scc-remediation-agent",
            "custom_details": {
                "approval_id": approval_id,
                "plan_summary": plan["summary"],
                "blast_level": impact["blast_level"],
                "prod_blast_count": impact["prod_blast_count"],
                "asset_env": impact["asset_env"],
                "asset_team": impact["asset_team"],
            },
        },
        "links": [],
    }

    try:
        async with aiohttp.ClientSession() as session:
            async with session.post(
                "https://events.pagerduty.com/v2/enqueue",
                json=payload,
                headers={"Content-Type": "application/json"},
                timeout=aiohttp.ClientTimeout(total=10),
            ) as resp:
                if resp.status not in (200, 202):
                    body = await resp.text()
                    print(f"[pagerduty] Unexpected status {resp.status}: {body}")
    except Exception as e:
        print(f"[pagerduty] Failed to send alert: {e}")


async def _create_jira_ticket(approval_id, plan, finding, impact, config):
    """Creates a Jira issue for approval via REST API."""
    import os

    jira_token = os.environ.get("JIRA_API_TOKEN", "")
    jira_email = os.environ.get("JIRA_EMAIL", "")
    base_url = config.notifications.jira_base_url
    project_key = config.notifications.jira_project_key

    if not all([jira_token, jira_email, base_url, project_key]):
        print("[jira] Missing Jira configuration — skipping")
        return

    description = (
        f"*Approval ID:* {approval_id}\n\n"
        f"*Finding:* {finding['severity']} — {finding['category']}\n"
        f"*Asset:* {finding['resource_name']}\n\n"
        f"*Plan summary:* {plan['summary']}\n\n"
        f"*Risk assessment:* {plan.get('risk_assessment', '')}\n\n"
        f"*Blast radius:* {impact['blast_level']} ({impact['prod_blast_count']} prod dependencies)\n\n"
        f"Reply APPROVED or REJECTED on this ticket to action the remediation."
    )

    payload = {
        "fields": {
            "project": {"key": project_key},
            "summary": f"[SCC Remediation Approval] {finding['severity']} on {finding['resource_name']}",
            "description": description,
            "issuetype": {"name": "Task"},
            "labels": ["scc-remediation", finding["severity"].lower()],
        }
    }

    import base64
    credentials = base64.b64encode(f"{jira_email}:{jira_token}".encode()).decode()

    try:
        async with aiohttp.ClientSession() as session:
            async with session.post(
                f"{base_url}/rest/api/2/issue",
                json=payload,
                headers={
                    "Authorization": f"Basic {credentials}",
                    "Content-Type": "application/json",
                },
                timeout=aiohttp.ClientTimeout(total=10),
            ) as resp:
                if resp.status == 201:
                    data = await resp.json()
                    print(f"[jira] Created issue {data.get('key')} for approval {approval_id}")
                else:
                    body = await resp.text()
                    print(f"[jira] Failed to create issue ({resp.status}): {body}")
    except Exception as e:
        print(f"[jira] Failed to create ticket: {e}")
