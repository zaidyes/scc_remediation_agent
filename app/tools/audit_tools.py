"""
Audit logging for the SCC Remediation Agent.

Every decision the agent makes is recorded here with its full reasoning chain
and outcome so security teams can review and audit all automated actions.

Two sinks are written to:
  1. Firestore  — `audit_log/{entry_id}` — primary, queryable by the UI
  2. BigQuery   — `audit_dataset.remediation_events` — analytics / SIEM
     BigQuery write is best-effort: a failure does not abort the pipeline.

`record_audit_entry` is also registered as an ADK FunctionTool so the agent
can write entries directly from its reasoning loop (e.g. to record why it chose
Tier 3 or why it skipped a finding).
"""
import datetime
import os
import uuid
from typing import Optional

from google.cloud import firestore


def record_audit_entry(
    event_type: str,
    finding_id: str,
    customer_id: str,
    severity: str = "",
    remediation_type: str = "",
    plan_id: str = "",
    outcome: str = "",
    reasoning: str = "",
    step_count: int = 0,
    approval_id: str = "",
    blast_level: str = "",
    confidence_score: float = 0.0,
    resource_name: str = "",
    extra: Optional[dict] = None,
) -> str:
    """
    Writes an immutable audit entry to Firestore and (best-effort) BigQuery.

    Args:
        event_type:        One of the EVENT_TYPE_* constants below.
        finding_id:        SCC finding ID.
        customer_id:       Tenant identifier.
        severity:          Finding severity (CRITICAL/HIGH/MEDIUM/LOW).
        remediation_type:  OS_PATCH / IAM / FIREWALL / MISCONFIGURATION.
        plan_id:           UUID of the remediation plan, if available.
        outcome:           SUCCESS / FAILURE / SKIPPED / DRY_RUN.
        reasoning:         Agent's free-text reasoning chain (truncated to 4 KB).
        step_count:        Number of plan steps executed.
        approval_id:       Approval record ID, if this decision required approval.
        blast_level:       LOW / MEDIUM / HIGH / CRITICAL.
        confidence_score:  Float 0.0-1.0.
        resource_name:     Full GCP resource name of the affected asset.
        extra:             Any additional key-value pairs to attach.

    Returns:
        The UUID of the created audit entry.
    """
    entry_id = str(uuid.uuid4())
    timestamp = datetime.datetime.utcnow()

    entry = {
        "entry_id":         entry_id,
        "event_type":       event_type,
        "finding_id":       finding_id,
        "customer_id":      customer_id,
        "severity":         severity,
        "remediation_type": remediation_type,
        "plan_id":          plan_id,
        "outcome":          outcome,
        "reasoning":        reasoning[:4096],   # cap to 4 KB
        "step_count":       step_count,
        "approval_id":      approval_id,
        "blast_level":      blast_level,
        "confidence_score": confidence_score,
        "resource_name":    resource_name,
        "timestamp":        timestamp,
        **(extra or {}),
    }

    # ── Firestore (primary sink) ──────────────────────────────────────────
    try:
        db = firestore.Client()
        db.collection("audit_log").document(entry_id).set(entry)
    except Exception as exc:
        # Firestore failure must not silently swallow findings — re-raise
        raise RuntimeError(f"audit_tools: Firestore write failed for {entry_id}") from exc

    # ── BigQuery (best-effort secondary sink) ─────────────────────────────
    _stream_to_bigquery(entry)

    return entry_id


def _stream_to_bigquery(entry: dict) -> None:
    """
    Streams a single audit entry to BigQuery. Failure is silently swallowed
    so a BQ outage cannot abort the remediation pipeline.

    The BigQuery dataset uses table-level ACLs:
      write-only for the agent service account,
      read-only for the security team.
    """
    dataset = os.environ.get("AUDIT_BQ_DATASET", "")
    project = os.environ.get("AUDIT_BQ_PROJECT", "")
    if not dataset or not project:
        return  # BQ sink not configured; skip silently

    try:
        from google.cloud import bigquery  # type: ignore

        bq = bigquery.Client(project=project)
        table_id = f"{project}.{dataset}.remediation_events"

        # BigQuery streaming insert requires serialisable values
        row = {k: (v.isoformat() if isinstance(v, datetime.datetime) else v)
               for k, v in entry.items()}

        errors = bq.insert_rows_json(table_id, [row])
        if errors:
            print(f"[audit] BigQuery insert errors for {entry['entry_id']}: {errors}")
    except Exception as exc:
        print(f"[audit] BigQuery stream failed (non-fatal): {exc}")


# ---------------------------------------------------------------------------
# Event type constants — use these rather than raw strings
# ---------------------------------------------------------------------------

EVENT_CYCLE_STARTED           = "CYCLE_STARTED"
EVENT_FINDING_SKIPPED         = "FINDING_SKIPPED"
EVENT_PLAN_BLOCKED            = "PLAN_BLOCKED"
EVENT_TIER_DECIDED            = "TIER_DECIDED"
EVENT_APPROVAL_DISPATCHED     = "APPROVAL_DISPATCHED"
EVENT_APPROVAL_RECEIVED       = "APPROVAL_RECEIVED"
EVENT_EXECUTION_STARTED       = "EXECUTION_STARTED"
EVENT_STEP_COMPLETED          = "STEP_COMPLETED"
EVENT_STEP_FAILED             = "STEP_FAILED"
EVENT_VERIFICATION_SUCCESS    = "VERIFICATION_SUCCESS"
EVENT_VERIFICATION_FAILED     = "VERIFICATION_FAILED"
EVENT_ROLLBACK_EXECUTED       = "ROLLBACK_EXECUTED"
EVENT_DRY_RUN                 = "DRY_RUN"
EVENT_CHANGE_FROZEN           = "CHANGE_FROZEN"
