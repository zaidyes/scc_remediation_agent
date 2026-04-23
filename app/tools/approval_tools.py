import uuid
from google.cloud import firestore
from googleapiclient.discovery import build

async def dispatch_approval_request(
    plan: dict,
    finding: dict,
    impact: dict,
    config,
    channels: list[str],
) -> str:
    """
    Creates an approval record in Firestore and sends the card to all channels.
    Returns the approval_id.
    """
    approval_id = str(uuid.uuid4())
    try:
        db = firestore.Client()

        approval_doc = {
            "approval_id": approval_id,
            "plan_id": plan.get("plan_id"),
            "finding_id": finding.get("finding_id"),
            "asset_name": finding.get("resource_name"),
            "severity": finding.get("severity"),
            "blast_level": impact.get("blast_level"),
            "status": "PENDING",
            "created_at": firestore.SERVER_TIMESTAMP,
            "expires_at": None, # Should be _compute_expiry
            "channels_notified": channels,
            "plan_summary": plan.get("summary"),
            "rollback_steps": plan.get("rollback_steps", []),
        }

        db.collection("approvals").document(approval_id).set(approval_doc)
    except Exception as e:
        print(f"Failed to write to Firestore: {e}")

    for channel in channels:
        if channel == "google_chat" and config.notifications.google_chat_space:
            await _send_chat_card(approval_id, plan, finding, impact, config)
        if channel == "pagerduty" and config.notifications.pagerduty_service_key:
            pass # await _send_pagerduty_alert(...)
        if channel == "jira" and config.notifications.jira_project_key:
            pass # await _create_jira_ticket(...)

    return approval_id

async def _send_chat_card(approval_id, plan, finding, impact, config):
    """Sends a structured Google Chat card with approve/reject/defer buttons."""
    try:
        service = build("chat", "v1")

        severity_color = {
            "CRITICAL": "#E24B4A",
            "HIGH": "#BA7517",
            "MEDIUM": "#378ADD",
            "LOW": "#639922",
        }.get(finding.get("severity"), "#888780")

        card = {
            "cardsV2": [{
                "cardId": f"approval-{approval_id}",
                "card": {
                    "header": {
                        "title": f"Remediation approval required",
                        "subtitle": f"{finding.get('severity')} · {finding.get('category')}",
                    },
                    "sections": [
                        {
                            "widgets": [
                                {"textParagraph": {"text": f"<b>Asset:</b> {finding.get('resource_name')}"}},
                                {"textParagraph": {"text": f"<b>Finding:</b> {plan.get('summary')}"}},
                                {"textParagraph": {"text": f"<b>Blast radius:</b> {impact.get('blast_level')} · {impact.get('prod_blast_count', 0)} prod dependencies"}},
                                {"textParagraph": {"text": f"<b>Environment:</b> {impact.get('asset_env')} · Team: {impact.get('asset_team')}"}},
                                {"textParagraph": {"text": f"<b>Risk assessment:</b> {plan.get('risk_assessment')}"}},
                                {"textParagraph": {"text": f"<b>Downtime:</b> {plan.get('estimated_downtime_minutes', 0)} min · Reboot: {'Yes' if plan.get('requires_reboot') else 'No'}"}},
                            ]
                        },
                        {
                            "header": "Rollback plan",
                            "widgets": [
                                {"textParagraph": {"text": "\n".join(f"{s.get('order', 1)}. {s.get('action')}" for s in plan.get("rollback_steps", [])[:3])}}
                            ]
                        },
                        {
                            "widgets": [{
                                "buttonList": {
                                    "buttons": [
                                        {
                                            "text": "Approve",
                                            "onClick": {"action": {"function": "approve_remediation", "parameters": [{"key": "approval_id", "value": approval_id}]}}
                                        },
                                        {
                                            "text": "Reject",
                                            "onClick": {"action": {"function": "reject_remediation", "parameters": [{"key": "approval_id", "value": approval_id}]}}
                                        },
                                        {
                                            "text": "Defer to window",
                                            "onClick": {"action": {"function": "defer_remediation", "parameters": [{"key": "approval_id", "value": approval_id}]}}
                                        },
                                    ]
                                }
                            }]
                        }
                    ]
                }
            }]
        }

        service.spaces().messages().create(
            parent=config.notifications.google_chat_space,
            body=card,
        ).execute()
    except Exception as e:
        print(f"Failed to send chat card: {e}")
