"""
Config UI backend API — deployed as a Cloud Run service, protected by IAP.
Serves all /api/* routes consumed by the React frontend.
"""
import os
import datetime
from typing import Any
from fastapi import FastAPI, HTTPException, Query
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
from google.cloud import firestore

app = FastAPI(title="SCC Remediation Agent — Config API")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)

_db: firestore.Client | None = None


def db() -> firestore.Client:
    global _db
    if _db is None:
        _db = firestore.Client()
    return _db


# ---------------------------------------------------------------------------
# Config routes
# ---------------------------------------------------------------------------

@app.get("/api/config/{customer_id}")
async def get_config(customer_id: str):
    doc = db().collection("configs").document(customer_id).get()
    if not doc.exists:
        raise HTTPException(status_code=404, detail="Config not found")
    return doc.to_dict()


@app.put("/api/config/{customer_id}")
async def save_config(customer_id: str, body: dict):
    """
    Saves config and increments version.
    Writes the previous version to /configs/{customer_id}/versions/{v}.
    """
    ref = db().collection("configs").document(customer_id)
    existing = ref.get()

    if existing.exists:
        prev = existing.to_dict()
        prev_version = prev.get("version", 1)
        db().collection("configs").document(customer_id) \
            .collection("versions").document(str(prev_version)).set(prev)
        body["version"] = prev_version + 1
    else:
        body["version"] = 1

    body["customer_id"] = customer_id
    body["updated_at"] = datetime.datetime.utcnow().isoformat()

    ref.set(body)
    return {"version": body["version"], "customer_id": customer_id}


@app.get("/api/config/{customer_id}/versions")
async def list_versions(customer_id: str):
    versions = (
        db().collection("configs").document(customer_id)
        .collection("versions")
        .order_by("version", direction=firestore.Query.DESCENDING)
        .stream()
    )
    return [{"version": v.to_dict().get("version"), "updated_at": v.to_dict().get("updated_at")} for v in versions]


@app.get("/api/config/{customer_id}/versions/{version}")
async def get_version(customer_id: str, version: int):
    doc = (
        db().collection("configs").document(customer_id)
        .collection("versions").document(str(version)).get()
    )
    if not doc.exists:
        raise HTTPException(status_code=404, detail="Version not found")
    return doc.to_dict()


@app.post("/api/config/validate")
async def validate_config(body: dict):
    from config.schema import CustomerConfig
    from config.validator import validate_and_preview

    try:
        config = CustomerConfig(**body)
    except Exception as e:
        return {"valid": False, "errors": [str(e)], "warnings": [], "preview": {}}

    result = await validate_and_preview(config)
    return result


@app.post("/api/config/preview-scope")
async def preview_scope(body: dict):
    """
    Counts assets in Neo4j matching the given scope config.
    Returns asset_count and a human-readable filter description.
    """
    from config.schema import ScopeConfig

    try:
        scope = ScopeConfig(**body.get("scope", {}))
    except Exception as e:
        raise HTTPException(status_code=400, detail=str(e))

    try:
        from app.tools.graph_tools import _run_query
        rows = _run_query("MATCH (r:Resource) RETURN r.asset_name AS name, r.project AS project, r.labels AS labels")
        matching = [r for r in rows if scope.matches_asset({"project": r.get("project", ""), "labels": r.get("labels") or {}})]
        asset_count = len(matching)
    except Exception:
        asset_count = 0

    filter_parts = []
    if scope.project_ids:
        filter_parts.append(f"projects: {', '.join(scope.project_ids)}")
    for f in scope.include_labels:
        filter_parts.append(f"{f.key}={f.value}")
    for f in scope.exclude_labels:
        filter_parts.append(f"NOT {f.key}={f.value}")

    return {
        "asset_count": asset_count,
        "filter_description": " AND ".join(filter_parts) if filter_parts else "All assets in org",
    }


@app.post("/api/config/simulate")
async def simulate(body: dict):
    """
    Dry-run simulation: how many findings would be actioned, how many auto-approved,
    who would receive approval requests.
    """
    from config.schema import CustomerConfig
    from config.validator import validate_and_preview

    try:
        config = CustomerConfig(**body)
    except Exception as e:
        raise HTTPException(status_code=400, detail=str(e))

    validation = await validate_and_preview(config)
    if not validation["valid"]:
        raise HTTPException(status_code=422, detail=validation["errors"])

    approver_summary = [
        {"name": a.name, "address": a.address, "severities": a.severity_levels}
        for a in config.approval_policy.approvers
    ]

    return {
        **validation["preview"],
        "approver_routing": approver_summary,
        "auto_approve_conditions": {
            "enabled": config.approval_policy.auto_approve_enabled,
            "max_blast_radius": config.execution.max_blast_radius_for_auto,
            "dry_run_active": config.dry_run,
        },
    }


# ---------------------------------------------------------------------------
# Findings routes
# ---------------------------------------------------------------------------

@app.get("/api/findings/active")
async def get_active_findings(
    customer_id: str = Query(...),
    limit: int = Query(50, le=200),
    offset: int = Query(0),
):
    docs = (
        db().collection("findings")
        .where("state", "==", "ACTIVE")
        .order_by("event_time", direction=firestore.Query.DESCENDING)
        .limit(limit)
        .stream()
    )

    findings = []
    for doc in docs:
        d = doc.to_dict()
        findings.append({
            "finding_id": d.get("finding_id"),
            "resource_name": d.get("resource_name"),
            "short_name": d.get("resource_name", "").split("/")[-1],
            "category": d.get("category"),
            "severity": d.get("severity"),
            "finding_class": d.get("finding_class"),
            "blast_level": d.get("blast_level"),
            "attack_exposure_score": d.get("attack_exposure_score", 0),
            "state": d.get("state"),
            "agent_status": d.get("agent_status", "triaging"),
            "event_time": d.get("event_time"),
            "plan_id": d.get("plan_id"),
        })

    return {"findings": findings, "total": len(findings), "offset": offset}


# ---------------------------------------------------------------------------
# Approvals routes
# ---------------------------------------------------------------------------

@app.get("/api/approvals/pending")
async def get_pending_approvals(customer_id: str = Query(...)):
    docs = (
        db().collection("approvals")
        .where("status", "==", "PENDING")
        .order_by("created_at", direction=firestore.Query.DESCENDING)
        .stream()
    )

    approvals = []
    for doc in docs:
        d = doc.to_dict()
        expires_at = d.get("expires_at")
        approvals.append({
            "approval_id": d.get("approval_id"),
            "finding_id": d.get("finding_id"),
            "asset_name": d.get("asset_name"),
            "severity": d.get("severity"),
            "blast_level": d.get("blast_level"),
            "plan_summary": d.get("plan_summary"),
            "status": d.get("status"),
            "created_at": d.get("created_at").isoformat() if hasattr(d.get("created_at"), "isoformat") else str(d.get("created_at")),
            "expires_at": expires_at.isoformat() if hasattr(expires_at, "isoformat") else str(expires_at),
            "channels_notified": d.get("channels_notified", []),
            "escalation_count": d.get("escalation_count", 0),
            "confidence_score": d.get("confidence_score"),
            "execution_tier": d.get("execution_tier"),
            "preflight_results": d.get("plan", {}).get("preflight_results", []),
            "executed_at": d.get("executed_at").isoformat() if hasattr(d.get("executed_at"), "isoformat") else d.get("executed_at"),
        })

    return {"approvals": approvals}


@app.post("/api/approval/{approval_id}/respond")
async def respond_to_approval(approval_id: str, body: dict):
    """
    Handles approval responses submitted from the UI dashboard.
    action: "APPROVED" | "REJECTED" | "DEFERRED"
    responder_email: str
    """
    action = body.get("action", "").upper()
    responder_email = body.get("responder_email", "ui-user@unknown")

    if action not in ("APPROVED", "REJECTED", "DEFERRED"):
        raise HTTPException(status_code=400, detail="action must be APPROVED, REJECTED, or DEFERRED")

    ref = db().collection("approvals").document(approval_id)
    doc = ref.get()
    if not doc.exists:
        raise HTTPException(status_code=404, detail="Approval not found")

    approval = doc.to_dict()
    if approval.get("status") != "PENDING":
        raise HTTPException(status_code=409, detail=f"Approval already {approval['status'].lower()}")

    customer_id = os.environ.get("CUSTOMER_ID", "")
    config_doc = db().collection("configs").document(customer_id).get()
    if not config_doc.exists:
        raise HTTPException(status_code=500, detail="Customer config not found")

    from config.schema import CustomerConfig
    config = CustomerConfig(**config_doc.to_dict())

    now = datetime.datetime.utcnow()
    update: dict[str, Any] = {
        "status": action,
        "responded_by": responder_email,
        "responded_at": now,
    }

    if action == "DEFERRED":
        from scheduler.windows import next_maintenance_window
        next_window = next_maintenance_window(config, approval["asset_name"])
        update["deferred_until"] = next_window

    ref.update(update)

    if action == "APPROVED":
        from scheduler.main import _enqueue_execution
        _enqueue_execution(approval_id, approval.get("plan", {}), config)

    _write_audit_entry(
        event_type=f"APPROVAL_{action}",
        finding_id=approval.get("finding_id"),
        asset_name=approval.get("asset_name"),
        detail=f"{action.capitalize()} by {responder_email} via UI",
        actor=responder_email,
    )

    return {"status": action, "approval_id": approval_id}


# ---------------------------------------------------------------------------
# Audit log
# ---------------------------------------------------------------------------

@app.get("/api/audit")
async def get_audit_log(
    customer_id: str = Query(...),
    limit: int = Query(50, le=200),
    page_token: str | None = Query(None),
):
    query = (
        db().collection("audit")
        .order_by("timestamp", direction=firestore.Query.DESCENDING)
        .limit(limit)
    )

    entries = []
    last_doc = None
    for doc in query.stream():
        d = doc.to_dict()
        ts = d.get("timestamp")
        entries.append({
            "entry_id": doc.id,
            "event_type": d.get("event_type"),
            "finding_id": d.get("finding_id"),
            "asset_name": d.get("asset_name"),
            "detail": d.get("detail"),
            "actor": d.get("actor", "agent"),
            "timestamp": ts.isoformat() if hasattr(ts, "isoformat") else str(ts),
        })
        last_doc = doc

    next_token = last_doc.id if last_doc and len(entries) == limit else None
    return {"entries": entries, "next_page_token": next_token}


# ---------------------------------------------------------------------------
# Rollback route
# ---------------------------------------------------------------------------

@app.post("/api/rollback/{approval_id}")
async def trigger_rollback(approval_id: str):
    """
    Executes the stored rollback artifact for an approval.
    Proxies to rollback_tools; only valid within 24 hours of execution.
    """
    from app.tools.rollback_tools import execute_rollback
    result = await execute_rollback(approval_id)
    if result["status"] == "FAILED":
        raise HTTPException(status_code=400, detail=result.get("output", "Rollback failed"))
    return result


# ---------------------------------------------------------------------------
# Policies CRUD + simulation
# ---------------------------------------------------------------------------

@app.get("/api/policies/{customer_id}")
async def list_policies(customer_id: str):
    """Returns all execution policies stored on the customer config."""
    config_doc = db().collection("configs").document(customer_id).get()
    if not config_doc.exists:
        raise HTTPException(status_code=404, detail="Config not found")
    raw_policies = config_doc.to_dict().get("policies", [])
    return raw_policies


@app.post("/api/policies/{customer_id}")
async def upsert_policy(customer_id: str, body: dict):
    """
    Creates or replaces a single execution policy on the customer config.
    Identifies the policy by policy_id; inserts if new, replaces if existing.
    """
    from config.policies import ExecutionPolicy as PolicyModel

    try:
        policy = PolicyModel(**body)
    except Exception as e:
        raise HTTPException(status_code=422, detail=str(e))

    config_ref = db().collection("configs").document(customer_id)
    config_doc = config_ref.get()
    if not config_doc.exists:
        raise HTTPException(status_code=404, detail="Config not found")

    current = config_doc.to_dict()
    policies: list = current.get("policies", [])
    policy_dict = policy.model_dump()

    idx = next((i for i, p in enumerate(policies) if p.get("policy_id") == policy.policy_id), None)
    if idx is not None:
        policies[idx] = policy_dict
    else:
        policies.append(policy_dict)

    config_ref.update({"policies": policies})
    return policy_dict


@app.delete("/api/policies/{customer_id}/{policy_id}")
async def remove_policy(customer_id: str, policy_id: str):
    """Removes a single execution policy by policy_id."""
    config_ref = db().collection("configs").document(customer_id)
    config_doc = config_ref.get()
    if not config_doc.exists:
        raise HTTPException(status_code=404, detail="Config not found")

    policies = config_doc.to_dict().get("policies", [])
    new_policies = [p for p in policies if p.get("policy_id") != policy_id]

    if len(new_policies) == len(policies):
        raise HTTPException(status_code=404, detail="Policy not found")

    config_ref.update({"policies": new_policies})
    return {"deleted": True, "policy_id": policy_id}


@app.post("/api/policies/{customer_id}/{policy_id}/simulate")
async def simulate_policy(customer_id: str, policy_id: str):
    """
    Runs a 30-day dry-run simulation of a single policy against recent Firestore
    audit log entries. Returns tier distribution and edge cases.
    """
    from config.policies import ExecutionPolicy as PolicyModel

    config_doc = db().collection("configs").document(customer_id).get()
    if not config_doc.exists:
        raise HTTPException(status_code=404, detail="Config not found")

    config_data = config_doc.to_dict()
    policy_raw = next(
        (p for p in config_data.get("policies", []) if p.get("policy_id") == policy_id),
        None,
    )
    if not policy_raw:
        raise HTTPException(status_code=404, detail="Policy not found")

    policy = PolicyModel(**policy_raw)

    import datetime
    cutoff = datetime.datetime.utcnow() - datetime.timedelta(days=30)
    findings_docs = (
        db().collection("findings")
        .where("event_time", ">=", cutoff.isoformat())
        .stream()
    )

    tier1 = tier2 = tier3 = 0
    edge_cases: list[str] = []

    for doc in findings_docs:
        f = doc.to_dict()
        blast = f.get("blast_level", "HIGH")
        matched = policy.matches(f, blast)
        if not matched:
            tier3 += 1
            continue

        confidence = f.get("confidence_score")
        if confidence is None:
            tier3 += 1
            edge_cases.append(
                f"No confidence score for {f.get('finding_id', doc.id)[:8]}… — defaulted to Tier 3"
            )
            continue

        if confidence < policy.min_confidence_threshold:
            tier3 += 1
            edge_cases.append(
                f"Confidence {confidence:.0%} below threshold for {f.get('category', 'unknown')} "
                f"on {f.get('resource_name', '')[-40:]}"
            )
            continue

        if policy.tier == 1:
            tier1 += 1
        else:
            tier2 += 1

    total = tier1 + tier2 + tier3
    return {
        "findings_evaluated": total,
        "would_execute_tier1": tier1,
        "would_execute_tier2": tier2,
        "would_execute_tier3": tier3,
        "edge_cases": edge_cases[:20],
    }


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _write_audit_entry(
    event_type: str,
    finding_id: str | None,
    asset_name: str | None,
    detail: str,
    actor: str = "agent",
) -> None:
    db().collection("audit").add({
        "event_type": event_type,
        "finding_id": finding_id,
        "asset_name": asset_name,
        "detail": detail,
        "actor": actor,
        "timestamp": firestore.SERVER_TIMESTAMP,
    })


if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8080)
