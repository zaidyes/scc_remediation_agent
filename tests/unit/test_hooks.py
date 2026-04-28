"""
Unit tests for app/hooks.py — registry, fire(), stop propagation, clear().

Built-in hooks (safety recheck, audit writer) are NOT tested here — they
require GCP clients. This file tests the dispatcher contract only.
"""
import asyncio
import pytest
import app.hooks as hooks


def _run(coro):
    return asyncio.get_event_loop().run_until_complete(coro)


@pytest.fixture(autouse=True)
def isolate_registry():
    """Clear all custom hooks before and after each test."""
    hooks.clear()
    yield
    hooks.clear()


# ---------------------------------------------------------------------------
# register() / on() decorator
# ---------------------------------------------------------------------------

def test_register_adds_hook():
    calls = []
    def my_hook(ctx): calls.append(1)
    hooks.register(hooks.PRE_FINDING, my_hook)
    _run(hooks.fire(hooks.PRE_FINDING, {"customer_id": "x", "finding_id": "f"}))
    assert calls == [1]

def test_on_decorator_registers_hook():
    calls = []
    @hooks.on(hooks.POST_PLAN)
    def my_hook(ctx): calls.append(2)
    _run(hooks.fire(hooks.POST_PLAN, {"customer_id": "x", "finding_id": "f"}))
    assert calls == [2]

def test_register_unknown_event_raises():
    with pytest.raises(ValueError, match="Unknown event"):
        hooks.register("not_a_real_event", lambda ctx: None)

def test_hooks_run_in_registration_order():
    order = []
    hooks.register(hooks.PRE_STEP, lambda ctx: order.append("first"))
    hooks.register(hooks.PRE_STEP, lambda ctx: order.append("second"))
    _run(hooks.fire(hooks.PRE_STEP, {"customer_id": "x", "finding_id": "f"}))
    assert order == ["first", "second"]


# ---------------------------------------------------------------------------
# Async hooks
# ---------------------------------------------------------------------------

def test_async_hook_is_awaited():
    results = []
    async def async_hook(ctx):
        results.append("async_ran")
    hooks.register(hooks.PRE_IMPACT, async_hook)
    _run(hooks.fire(hooks.PRE_IMPACT, {"customer_id": "x", "finding_id": "f"}))
    assert results == ["async_ran"]


# ---------------------------------------------------------------------------
# ctx mutation and replacement
# ---------------------------------------------------------------------------

def test_hook_returning_none_keeps_ctx():
    def my_hook(ctx):
        ctx["added"] = True
        return None  # explicit None — ctx is mutated in-place
    hooks.register(hooks.PRE_PLAN, my_hook)
    ctx = _run(hooks.fire(hooks.PRE_PLAN, {"customer_id": "x", "finding_id": "f"}))
    assert ctx["added"] is True

def test_hook_returning_new_dict_replaces_ctx():
    def my_hook(ctx):
        return {"replaced": True, "event": ctx["event"]}
    hooks.register(hooks.PRE_EXECUTE, my_hook)
    ctx = _run(hooks.fire(hooks.PRE_EXECUTE, {"customer_id": "x", "finding_id": "f"}))
    assert ctx.get("replaced") is True

def test_fire_sets_event_key():
    ctx = _run(hooks.fire(hooks.ON_BLOCK, {"customer_id": "x", "finding_id": "f"}))
    assert ctx["event"] == hooks.ON_BLOCK

def test_fire_does_not_overwrite_existing_event_key():
    ctx = _run(hooks.fire(hooks.ON_BLOCK, {"event": "already_set", "customer_id": "x", "finding_id": "f"}))
    assert ctx["event"] == "already_set"


# ---------------------------------------------------------------------------
# stop propagation
# ---------------------------------------------------------------------------

def test_stop_halts_subsequent_hooks():
    order = []
    def stopper(ctx):
        ctx["stop"] = True
        ctx["stop_reason"] = "test"
        order.append("stopper")
    def should_not_run(ctx):
        order.append("should_not_run")

    hooks.register(hooks.PRE_STEP, stopper)
    hooks.register(hooks.PRE_STEP, should_not_run)
    ctx = _run(hooks.fire(hooks.PRE_STEP, {"customer_id": "x", "finding_id": "f"}))

    assert order == ["stopper"]
    assert ctx["stop"] is True
    assert ctx["stop_reason"] == "test"

def test_stop_false_does_not_halt():
    order = []
    hooks.register(hooks.PRE_STEP, lambda ctx: order.append(1))
    hooks.register(hooks.PRE_STEP, lambda ctx: order.append(2))
    _run(hooks.fire(hooks.PRE_STEP, {"customer_id": "x", "finding_id": "f", "stop": False}))
    assert order == [1, 2]


# ---------------------------------------------------------------------------
# Exception handling
# ---------------------------------------------------------------------------

def test_exception_in_hook_does_not_propagate():
    def bad_hook(ctx):
        raise RuntimeError("boom")
    after_calls = []
    hooks.register(hooks.POST_STEP, bad_hook)
    hooks.register(hooks.POST_STEP, lambda ctx: after_calls.append(1))
    # Should not raise
    _run(hooks.fire(hooks.POST_STEP, {"customer_id": "x", "finding_id": "f"}))
    assert after_calls == [1]

def test_exception_does_not_stop_pipeline():
    calls = []
    def raises(ctx): raise ValueError("test")
    def runs(ctx): calls.append("ran")
    hooks.register(hooks.POST_VERIFY, raises)
    hooks.register(hooks.POST_VERIFY, runs)
    _run(hooks.fire(hooks.POST_VERIFY, {"customer_id": "x", "finding_id": "f"}))
    assert calls == ["ran"]


# ---------------------------------------------------------------------------
# clear()
# ---------------------------------------------------------------------------

def test_clear_specific_event():
    calls = []
    hooks.register(hooks.PRE_FINDING, lambda ctx: calls.append(1))
    hooks.register(hooks.POST_FINDING, lambda ctx: calls.append(2))
    hooks.clear(hooks.PRE_FINDING)
    _run(hooks.fire(hooks.PRE_FINDING, {"customer_id": "x", "finding_id": "f"}))
    _run(hooks.fire(hooks.POST_FINDING, {"customer_id": "x", "finding_id": "f"}))
    assert calls == [2]  # PRE_FINDING hook removed; POST_FINDING still runs

def test_clear_all_events():
    calls = []
    hooks.register(hooks.PRE_FINDING, lambda ctx: calls.append(1))
    hooks.register(hooks.PRE_PLAN, lambda ctx: calls.append(2))
    hooks.clear()
    _run(hooks.fire(hooks.PRE_FINDING, {"customer_id": "x", "finding_id": "f"}))
    _run(hooks.fire(hooks.PRE_PLAN, {"customer_id": "x", "finding_id": "f"}))
    assert calls == []


# ---------------------------------------------------------------------------
# ALL_EVENTS completeness
# ---------------------------------------------------------------------------

def test_all_events_has_24_entries():
    assert len(hooks.ALL_EVENTS) == 24

def test_all_event_constants_in_all_events():
    declared = {
        hooks.PRE_FINDING, hooks.POST_FINDING,
        hooks.PRE_IMPACT, hooks.POST_IMPACT,
        hooks.PRE_PREFLIGHT, hooks.POST_PREFLIGHT,
        hooks.PRE_PLAN, hooks.POST_PLAN,
        hooks.PRE_TIER_DECISION, hooks.POST_TIER_DECISION,
        hooks.PRE_EXECUTE, hooks.POST_EXECUTE,
        hooks.PRE_STEP, hooks.POST_STEP,
        hooks.PRE_VERIFY, hooks.POST_VERIFY,
        hooks.PRE_APPROVAL_DISPATCH, hooks.POST_APPROVAL_DISPATCH,
        hooks.ON_BLOCK, hooks.ON_STEP_FAILURE, hooks.ON_VERIFY_FAILURE,
        hooks.ON_REGRESSION_DETECTED, hooks.ON_DRY_RUN, hooks.ON_INVALIDATION,
    }
    assert declared == set(hooks.ALL_EVENTS)
