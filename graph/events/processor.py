"""
Event processor — Cloud Run service with two Pub/Sub push endpoints.

  POST /events/asset   receives CAI feed events (asset-change-events topic)
  POST /events/audit   receives Cloud Audit Log events (audit-change-events topic)

Pipeline per message:
  1. Decode Pub/Sub envelope
  2. Idempotency check (message_id in /processed_events)
  3. filter.classify_change() — discard if None
  4. handlers.handle_*() — update Neo4j graph
  5. proximity_index.get_affected_approvals() — find affected approvals
  6. invalidation.determine_response() + apply_response() per approval
"""
import base64
import json
import os
from contextlib import asynccontextmanager
from datetime import datetime, timedelta

from fastapi import FastAPI, HTTPException, Request, status
from google.cloud import firestore
from neo4j import AsyncGraphDatabase

from graph.events.filter import classify_change
from graph.events.handlers import (
    handle_iam_change,
    handle_relationship_change,
    handle_resource_change,
)
from graph.events.invalidation import apply_response, determine_response
from graph.events.proximity_index import get_affected_approvals

# --------------------------------------------------------------------------- #
# App setup
# --------------------------------------------------------------------------- #

_neo4j_driver = None


@asynccontextmanager
async def lifespan(app: FastAPI):
    global _neo4j_driver
    _neo4j_driver = AsyncGraphDatabase.driver(
        os.environ["NEO4J_URI"],
        auth=("neo4j", os.environ["NEO4J_PASSWORD"]),
    )
    yield
    await _neo4j_driver.close()


app = FastAPI(title="SCC Agent Event Processor", lifespan=lifespan)

# --------------------------------------------------------------------------- #
# Endpoints
# --------------------------------------------------------------------------- #

@app.post("/events/asset", status_code=status.HTTP_204_NO_CONTENT)
async def handle_asset_event(request: Request):
    """Receives CAI feed events from the asset-change-events Pub/Sub topic."""
    envelope = await request.json()
    event = _decode_pubsub(envelope)
    await _process_event(event, envelope.get("message", {}).get("messageId", ""))


@app.post("/events/audit", status_code=status.HTTP_204_NO_CONTENT)
async def handle_audit_event(request: Request):
    """Receives Cloud Audit Log events from the audit-change-events topic."""
    envelope = await request.json()
    event = _decode_pubsub(envelope)
    await _process_event(event, envelope.get("message", {}).get("messageId", ""))


@app.get("/healthz")
async def healthz():
    return {"status": "ok"}


# --------------------------------------------------------------------------- #
# Core pipeline
# --------------------------------------------------------------------------- #

async def _process_event(event: dict, message_id: str) -> None:
    # 1. Idempotency — skip if already processed
    if message_id and not await _claim_message(message_id):
        return

    # 2. Filter — discard immaterial events
    change = classify_change(event)
    if change is None:
        return

    # 3. Graph update
    async with _neo4j_driver.session() as session:
        content_type = change["content_type"]
        if content_type == "IAM_POLICY":
            await handle_iam_change(change, session)
        elif content_type == "RELATIONSHIP":
            await handle_relationship_change(change, session)
        else:
            await handle_resource_change(change, session)

    # 4. Proximity lookup
    affected_approval_ids = get_affected_approvals(change["asset_name"])
    if not affected_approval_ids:
        return

    # 5. Invalidation — load each approval and determine response
    db = firestore.AsyncClient()
    for approval_id in affected_approval_ids:
        doc = await db.collection("approvals").document(approval_id).get()
        if not doc.exists:
            continue

        approval = doc.to_dict()
        # Only act on live approvals
        if approval.get("status") not in ("PENDING", "APPROVED"):
            continue

        # Check the change affects the remediation type of this approval
        approval_rem_type = approval.get("plan", {}).get("remediation_type", "")
        if approval_rem_type not in change["affected_remediation_types"]:
            continue

        response = determine_response(change, approval)
        await apply_response(response, change, approval_id)


# --------------------------------------------------------------------------- #
# Idempotency helpers
# --------------------------------------------------------------------------- #

async def _claim_message(message_id: str) -> bool:
    """
    Atomically claims a message ID. Returns True if this is the first time
    we're processing it, False if it was already processed.
    TTL: 24 hours (set via Firestore TTL policy on the `expires_at` field).
    """
    db = firestore.AsyncClient()
    doc_ref = db.collection("processed_events").document(message_id)

    try:
        await db.run_transaction(_claim_transaction, doc_ref)
        return True
    except AlreadyProcessed:
        return False


class AlreadyProcessed(Exception):
    pass


async def _claim_transaction(transaction, doc_ref):
    doc = await transaction.get(doc_ref)
    if doc.exists:
        raise AlreadyProcessed()
    transaction.set(doc_ref, {
        "processed_at": datetime.utcnow().isoformat(),
        "expires_at": datetime.utcnow() + timedelta(hours=24),
    })


# --------------------------------------------------------------------------- #
# Pub/Sub helpers
# --------------------------------------------------------------------------- #

def _decode_pubsub(envelope: dict) -> dict:
    """Decodes the base64 Pub/Sub message data field."""
    message = envelope.get("message", {})
    data = message.get("data", "")
    if not data:
        raise HTTPException(status_code=400, detail="Empty Pub/Sub message data")
    try:
        decoded = base64.b64decode(data).decode("utf-8")
        return json.loads(decoded)
    except Exception as e:
        raise HTTPException(status_code=400, detail=f"Could not decode message: {e}")


# --------------------------------------------------------------------------- #
# Entrypoint
# --------------------------------------------------------------------------- #

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(
        "graph.events.processor:app",
        host="0.0.0.0",
        port=int(os.environ.get("PORT", 8090)),
    )
