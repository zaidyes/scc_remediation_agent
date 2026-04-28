"""
Event hook pipeline for the SCC Remediation Agent.

Architecture based on the Claude Code harness pattern (arXiv 2604.14228):
  - Zero LLM context cost — hooks run entirely outside model calls
  - Any hook can halt the pipeline by setting ctx["stop"] = True
  - Hooks are async; sync hooks are wrapped transparently
  - Built-in hooks are registered at import time
  - Customer hooks can be registered via register() or the AGENT_HOOKS env var

Event lifecycle (24 events):

  Pre/Post pipeline stages:
    pre_finding          post_finding
    pre_impact           post_impact
    pre_preflight        post_preflight
    pre_plan             post_plan
    pre_tier_decision    post_tier_decision
    pre_execute          post_execute
    pre_step             post_step          ← per remediation step; stop=True halts execution
    pre_verify           post_verify
    pre_approval_dispatch  post_approval_dispatch

  Failure / special events:
    on_block              — plan blocked by pre-flight BLOCK result
    on_step_failure       — individual execution step failed
    on_verify_failure     — post-execution verification failed
    on_regression_detected — regression monitor triggered rollback
    on_dry_run            — action suppressed by dry_run flag
    on_invalidation       — approval invalidated by event processor

ctx contract:
  Every ctx dict always contains at minimum:
    event        str       — the event name
    customer_id  str       — customer ID
    finding_id   str       — current finding ID (empty string if not yet known)
    config       object    — CustomerConfig (or None)

  Hooks may freely add, read, or modify any key. The mutated ctx is
  passed to the next hook in the chain. Returning None keeps the ctx
  unchanged; returning a new dict replaces it.

  To halt the pipeline:
    ctx["stop"] = True
    ctx["stop_reason"] = "human-readable explanation"  # optional but encouraged
"""
import inspect
from collections import defaultdict
from typing import Callable

# ---------------------------------------------------------------------------
# Event name constants
# ---------------------------------------------------------------------------

PRE_FINDING           = "pre_finding"
POST_FINDING          = "post_finding"
PRE_IMPACT            = "pre_impact"
POST_IMPACT           = "post_impact"
PRE_PREFLIGHT         = "pre_preflight"
POST_PREFLIGHT        = "post_preflight"
PRE_PLAN              = "pre_plan"
POST_PLAN             = "post_plan"
PRE_TIER_DECISION     = "pre_tier_decision"
POST_TIER_DECISION    = "post_tier_decision"
PRE_EXECUTE           = "pre_execute"
POST_EXECUTE          = "post_execute"
PRE_STEP              = "pre_step"
POST_STEP             = "post_step"
PRE_VERIFY            = "pre_verify"
POST_VERIFY           = "post_verify"
PRE_APPROVAL_DISPATCH = "pre_approval_dispatch"
POST_APPROVAL_DISPATCH = "post_approval_dispatch"

ON_BLOCK               = "on_block"
ON_STEP_FAILURE        = "on_step_failure"
ON_VERIFY_FAILURE      = "on_verify_failure"
ON_REGRESSION_DETECTED = "on_regression_detected"
ON_DRY_RUN             = "on_dry_run"
ON_INVALIDATION        = "on_invalidation"

ALL_EVENTS = [
    PRE_FINDING, POST_FINDING,
    PRE_IMPACT, POST_IMPACT,
    PRE_PREFLIGHT, POST_PREFLIGHT,
    PRE_PLAN, POST_PLAN,
    PRE_TIER_DECISION, POST_TIER_DECISION,
    PRE_EXECUTE, POST_EXECUTE,
    PRE_STEP, POST_STEP,
    PRE_VERIFY, POST_VERIFY,
    PRE_APPROVAL_DISPATCH, POST_APPROVAL_DISPATCH,
    ON_BLOCK, ON_STEP_FAILURE, ON_VERIFY_FAILURE,
    ON_REGRESSION_DETECTED, ON_DRY_RUN, ON_INVALIDATION,
]

# ---------------------------------------------------------------------------
# Registry
# ---------------------------------------------------------------------------

_registry: dict[str, list[Callable]] = defaultdict(list)


def register(event: str, fn: Callable) -> None:
    """Registers a hook for a specific event."""
    if event not in ALL_EVENTS:
        raise ValueError(f"Unknown event '{event}'. Valid events: {ALL_EVENTS}")
    _registry[event].append(fn)


def on(event: str):
    """Decorator shorthand for register()."""
    def decorator(fn: Callable) -> Callable:
        register(event, fn)
        return fn
    return decorator


def clear(event: str | None = None) -> None:
    """Removes all hooks for an event, or all hooks if event is None. Mainly for tests."""
    if event is None:
        _registry.clear()
    else:
        _registry[event].clear()


# ---------------------------------------------------------------------------
# Dispatcher
# ---------------------------------------------------------------------------

async def fire(event: str, ctx: dict) -> dict:
    """
    Fires all registered hooks for an event in registration order.

    Returns the final ctx dict (potentially mutated or replaced by hooks).
    Stops early if any hook sets ctx["stop"] = True.
    Exceptions inside hooks are caught and logged; they do not propagate
    unless the hook already set stop=True.
    """
    ctx.setdefault("event", event)
    for hook in _registry[event]:
        try:
            if inspect.iscoroutinefunction(hook):
                result = await hook(ctx)
            else:
                result = hook(ctx)
            if result is not None:
                ctx = result
        except Exception as exc:
            print(f"[hooks] Error in {event} hook '{hook.__name__}': {exc}")
        if ctx.get("stop"):
            break
    return ctx


# ---------------------------------------------------------------------------
# Built-in hook: per-step safety re-check
#
# Addresses the plan-vs-action gap: once a plan is approved, the approval
# status and change freeze are re-evaluated before every individual step.
# Mirrors Claude Code's per-action permission gate.
# ---------------------------------------------------------------------------

async def _builtin_per_step_safety_recheck(ctx: dict) -> dict:
    """
    Re-checks change freeze and approval liveness before each execution step.
    Registered on PRE_STEP.
    """
    from scheduler.freeze import is_change_frozen

    config = ctx.get("config")
    finding = ctx.get("finding", {})
    resource_name = finding.get("resource_name", "")
    approval_id = ctx.get("approval_id")

    # Re-check change freeze (may have been applied after plan was approved)
    if config and resource_name and is_change_frozen(resource_name, config):
        ctx["stop"] = True
        ctx["stop_reason"] = "change_freeze_detected_mid_execution"
        print(
            f"[hooks] PRE_STEP: change freeze on {resource_name} — "
            f"halting execution of step {ctx.get('step', {}).get('order', '?')}"
        )
        return ctx

    # Re-check approval liveness (may have been invalidated by event processor)
    if approval_id:
        try:
            from google.cloud import firestore as _fs
            db = _fs.Client()
            doc = db.collection("approvals").document(approval_id).get()
            if doc.exists:
                status = doc.to_dict().get("status", "PENDING")
                if status in ("INVALIDATED", "BLOCKED", "REJECTED"):
                    ctx["stop"] = True
                    ctx["stop_reason"] = f"approval_{status.lower()}_during_execution"
                    print(
                        f"[hooks] PRE_STEP: approval {approval_id} is now {status} — "
                        f"halting execution"
                    )
                    return ctx
        except Exception as exc:
            print(f"[hooks] PRE_STEP: could not verify approval status: {exc}")

    return ctx


# ---------------------------------------------------------------------------
# Built-in hook: audit log writer
#
# Replaces scattered print() + ad-hoc Firestore writes with a single
# declarative audit hook. Fires on key post-/failure events.
# ---------------------------------------------------------------------------

_AUDIT_EVENT_MAP: dict[str, str] = {
    POST_PLAN:              "PLAN_GENERATED",
    ON_BLOCK:               "PLAN_BLOCKED",
    POST_EXECUTE:           "EXECUTION_COMPLETE",
    ON_STEP_FAILURE:        "STEP_FAILED",
    POST_VERIFY:            "VERIFICATION_COMPLETE",
    ON_VERIFY_FAILURE:      "VERIFICATION_FAILED",
    ON_REGRESSION_DETECTED: "REGRESSION_DETECTED",
    POST_APPROVAL_DISPATCH: "APPROVAL_DISPATCHED",
    ON_DRY_RUN:             "DRY_RUN_SUPPRESSED",
    ON_INVALIDATION:        "APPROVAL_INVALIDATED",
}


async def _builtin_audit_writer(ctx: dict) -> None:
    """
    Writes a structured audit entry to Firestore for key pipeline events.
    Registered on all events in _AUDIT_EVENT_MAP.
    """
    event = ctx.get("event", "")
    audit_type = _AUDIT_EVENT_MAP.get(event)
    if not audit_type:
        return

    finding = ctx.get("finding", {})
    detail_parts: list[str] = []

    if event == POST_PLAN:
        plan = ctx.get("plan", {})
        detail_parts = [
            f"type={plan.get('remediation_type', '?')}",
            f"confidence={plan.get('confidence_score', 0):.0%}",
            f"tier={ctx.get('tier', '?')}",
        ]
    elif event == ON_BLOCK:
        detail_parts = [f"reason={ctx.get('block_reason', ctx.get('plan', {}).get('block_reason', '?'))}"]
    elif event == POST_EXECUTE:
        detail_parts = [f"steps_completed={ctx.get('steps_completed', '?')}"]
    elif event == ON_STEP_FAILURE:
        step = ctx.get("step", {})
        detail_parts = [f"step={step.get('order', '?')} ({step.get('action', '?')})", f"error={ctx.get('error', '?')}"]
    elif event in (POST_VERIFY, ON_VERIFY_FAILURE):
        detail_parts = [f"result={ctx.get('verify_result', {}).get('status', '?')}"]
    elif event == ON_REGRESSION_DETECTED:
        detail_parts = [f"asset={ctx.get('regressed_asset', '?')}"]
    elif event == POST_APPROVAL_DISPATCH:
        detail_parts = [f"approval_id={ctx.get('approval_id', '?')}", f"tier={ctx.get('tier', '?')}"]
    elif event == ON_INVALIDATION:
        detail_parts = [f"reason={ctx.get('invalidation_reason', '?')}"]

    detail = " | ".join(detail_parts)

    try:
        from google.cloud import firestore as _fs
        db = _fs.AsyncClient()
        await db.collection("audit_log").add({
            "event_type":   audit_type,
            "finding_id":   ctx.get("finding_id") or finding.get("finding_id"),
            "asset_name":   ctx.get("asset_name") or finding.get("resource_name"),
            "customer_id":  ctx.get("customer_id", ""),
            "plan_id":      ctx.get("plan_id") or ctx.get("plan", {}).get("plan_id"),
            "detail":       detail,
            "actor":        "agent",
            "timestamp":    _fs.SERVER_TIMESTAMP,
        })
    except Exception as exc:
        print(f"[hooks] Audit write failed for {audit_type}: {exc}")


# ---------------------------------------------------------------------------
# Built-in hook: agent reasoning transcript logger
#
# Opt-in (requires AGENT_LOG_REASONING=true env var or config flag).
# Writes LLM message lists to /agent_sessions/{finding_id}/{agent_name}
# for offline replay and eval against real production sessions.
# ---------------------------------------------------------------------------

async def _builtin_transcript_logger(ctx: dict) -> None:
    """
    Persists agent reasoning messages for post-hoc auditability.
    Registered on POST_IMPACT, POST_PLAN, POST_VERIFY.
    Gated by AGENT_LOG_REASONING env var.
    """
    import os
    if os.environ.get("AGENT_LOG_REASONING", "").lower() not in ("1", "true", "yes"):
        return

    event = ctx.get("event", "")
    messages = ctx.get("messages")
    if not messages:
        return

    agent_name = {
        POST_IMPACT: "impact_agent",
        POST_PLAN:   "plan_agent",
        POST_VERIFY: "verify_agent",
    }.get(event)
    if not agent_name:
        return

    finding_id = ctx.get("finding_id", "unknown")

    try:
        from google.cloud import firestore as _fs
        import datetime
        db = _fs.AsyncClient()
        await (
            db.collection("agent_sessions")
            .document(finding_id)
            .collection(agent_name)
            .add({
                "messages":    messages,
                "finding_id":  finding_id,
                "plan_id":     ctx.get("plan_id"),
                "customer_id": ctx.get("customer_id"),
                "recorded_at": datetime.datetime.utcnow().isoformat(),
            })
        )
    except Exception as exc:
        print(f"[hooks] Transcript write failed for {agent_name}/{finding_id}: {exc}")


# ---------------------------------------------------------------------------
# Register built-in hooks
# ---------------------------------------------------------------------------

register(PRE_STEP, _builtin_per_step_safety_recheck)

for _event in _AUDIT_EVENT_MAP:
    register(_event, _builtin_audit_writer)

register(POST_IMPACT, _builtin_transcript_logger)
register(POST_PLAN,   _builtin_transcript_logger)
register(POST_VERIFY, _builtin_transcript_logger)
