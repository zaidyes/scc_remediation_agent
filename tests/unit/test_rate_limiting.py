"""
Tests for rate limiting in app/main.py:
  - max_findings_per_cycle caps the batch
  - Semaphore limits concurrency
  - Per-finding timeout skips hung findings without blocking the cycle
"""
import asyncio
import sys
import types as _types
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

# Stub GCP packages before importing app modules
for _name in (
    "google.cloud.compute_v1",
    "google.cloud.logging_v2",
    "google.cloud.osconfig_v1",
    "google.cloud.osconfig_v1.types",
    "google.cloud.osconfig_v1.types.inventory",
    "google.cloud.asset_v1",
    "google.cloud.firestore",
    "google.cloud.securitycenter_v2",
    "google.cloud.tasks_v2",
):
    if _name not in sys.modules:
        mod = _types.ModuleType(_name)
        sys.modules[_name] = mod

# Stub ADK and agent modules that cascade-import GCP SDKs
for _name in (
    "google.adk",
    "google.adk.agents",
    "google.adk.tools",
    "google.adk.tools.function_tool",
    "google.adk.runners",
    "google.genai",
    "google.genai.types",
    "app.agents.preflight_agent",
    "app.agents.triage_agent",
    "app.agents.impact_agent",
    "app.agents.dormancy_agent",
    "app.agents.plan_agent",
    "app.agents.verify_agent",
    "app.agent",
    "app.tools.approval_tools",
    "app.tools.osconfig_tools",
    "app.tools.confidence",
    "app.tools.agent_output",
    "app.tools.neo4j_tools",
    "app.tools.validate_plan_tool",
    "app.hooks",
    "scheduler.freeze",
    "config.policies",
):
    if _name not in sys.modules:
        stub = _types.ModuleType(_name)
        sys.modules[_name] = stub

# Provide minimal ADK symbols
sys.modules["google.adk.agents"].Agent = MagicMock
sys.modules["google.adk.tools"].FunctionTool = MagicMock
sys.modules["google.adk.tools.function_tool"].FunctionTool = MagicMock
sys.modules["app.agent"].root_agent = MagicMock()

# Symbols imported by app/main.py from its stubs
sys.modules["app.agents.triage_agent"].TriageAgent = MagicMock
sys.modules["app.agents.impact_agent"].ImpactAgent = MagicMock
sys.modules["app.agents.dormancy_agent"].DormancyAgent = MagicMock
sys.modules["app.agents.plan_agent"].PlanAgent = MagicMock
sys.modules["app.agents.verify_agent"].VerifyAgent = MagicMock
sys.modules["app.tools.approval_tools"].dispatch_approval_request = AsyncMock()
sys.modules["app.tools.osconfig_tools"].create_patch_job = MagicMock()
sys.modules["app.tools.confidence"].compute_confidence_score = MagicMock(return_value=0.8)
sys.modules["app.tools.agent_output"].compact_impact_for_approval = MagicMock(return_value={})
sys.modules["app.tools.agent_output"].compact_impact_for_scoring = MagicMock(return_value={"blast_level": "LOW"})

# Firestore stub
_fs = sys.modules["google.cloud.firestore"]
_fs.Client = MagicMock
_fs.AsyncClient = MagicMock
_fs.Increment = MagicMock
_fs.SERVER_TIMESTAMP = None
_fs.Query = MagicMock()

# Provide minimal symbols used by main.py
sys.modules["app.hooks"].PRE_FINDING = "PRE_FINDING"
sys.modules["app.hooks"].POST_FINDING = "POST_FINDING"
sys.modules["app.hooks"].PRE_IMPACT = "PRE_IMPACT"
sys.modules["app.hooks"].POST_IMPACT = "POST_IMPACT"
sys.modules["app.hooks"].PRE_PLAN = "PRE_PLAN"
sys.modules["app.hooks"].POST_PLAN = "POST_PLAN"
sys.modules["app.hooks"].PRE_TIER_DECISION = "PRE_TIER_DECISION"
sys.modules["app.hooks"].POST_TIER_DECISION = "POST_TIER_DECISION"
sys.modules["app.hooks"].PRE_EXECUTE = "PRE_EXECUTE"
sys.modules["app.hooks"].POST_EXECUTE = "POST_EXECUTE"
sys.modules["app.hooks"].PRE_STEP = "PRE_STEP"
sys.modules["app.hooks"].POST_STEP = "POST_STEP"
sys.modules["app.hooks"].PRE_VERIFY = "PRE_VERIFY"
sys.modules["app.hooks"].POST_VERIFY = "POST_VERIFY"
sys.modules["app.hooks"].PRE_APPROVAL_DISPATCH = "PRE_APPROVAL_DISPATCH"
sys.modules["app.hooks"].POST_APPROVAL_DISPATCH = "POST_APPROVAL_DISPATCH"
sys.modules["app.hooks"].ON_BLOCK = "ON_BLOCK"
sys.modules["app.hooks"].ON_DRY_RUN = "ON_DRY_RUN"
sys.modules["app.hooks"].ON_STEP_FAILURE = "ON_STEP_FAILURE"
sys.modules["app.hooks"].ON_VERIFY_FAILURE = "ON_VERIFY_FAILURE"
sys.modules["app.hooks"].ON_REGRESSION_DETECTED = "ON_REGRESSION_DETECTED"
sys.modules["app.hooks"].ON_INVALIDATION = "ON_INVALIDATION"

async def _noop_fire(event, ctx):
    return ctx

sys.modules["app.hooks"].fire = _noop_fire
sys.modules["scheduler.freeze"].is_change_frozen = lambda resource, config: False
sys.modules["config.policies"].ExecutionPolicy = MagicMock


def _make_config(max_per_cycle=20, timeout_s=300, max_concurrent=5):
    from config.schema import ExecutionConfig, CustomerConfig, ScopeConfig, ApprovalPolicy
    exec_cfg = ExecutionConfig(
        max_findings_per_cycle=max_per_cycle,
        finding_timeout_seconds=timeout_s,
    )
    cfg = MagicMock(spec=CustomerConfig)
    cfg.customer_id = "cust-1"
    cfg.dry_run = True
    cfg.execution = exec_cfg
    cfg.policies = []
    return cfg


def _make_findings(n: int) -> list[dict]:
    return [
        {
            "finding_id": f"finding-{i}",
            "severity": "HIGH",
            "resource_name": f"//cloudresourcemanager.googleapis.com/projects/proj-{i}",
        }
        for i in range(n)
    ]


# ---------------------------------------------------------------------------
# max_findings_per_cycle cap
# ---------------------------------------------------------------------------

class TestMaxFindingsPerCycle:

    @pytest.mark.asyncio
    async def test_batch_capped_at_max(self):
        """Only max_findings_per_cycle findings are processed even if triage returns more."""
        import app.main as main_mod

        findings = _make_findings(30)
        config = _make_config(max_per_cycle=5)
        processed = []

        async def _fake_process(finding, cfg, policies):
            processed.append(finding["finding_id"])

        triage_stub = MagicMock()
        triage_stub.run = AsyncMock(return_value=findings)

        with patch.object(main_mod, "TriageAgent", return_value=triage_stub), \
             patch.object(main_mod, "_process_finding", side_effect=_fake_process), \
             patch.object(main_mod, "_pipeline_sem", None):
            await main_mod.run_remediation_cycle(config)

        assert len(processed) == 5
        assert processed == [f"finding-{i}" for i in range(5)]

    @pytest.mark.asyncio
    async def test_batch_smaller_than_max_all_processed(self):
        """If triage returns fewer than max, all are processed."""
        import app.main as main_mod

        findings = _make_findings(3)
        config = _make_config(max_per_cycle=20)
        processed = []

        async def _fake_process(finding, cfg, policies):
            processed.append(finding["finding_id"])

        triage_stub = MagicMock()
        triage_stub.run = AsyncMock(return_value=findings)

        with patch.object(main_mod, "TriageAgent", return_value=triage_stub), \
             patch.object(main_mod, "_process_finding", side_effect=_fake_process), \
             patch.object(main_mod, "_pipeline_sem", None):
            await main_mod.run_remediation_cycle(config)

        assert len(processed) == 3


# ---------------------------------------------------------------------------
# Per-finding timeout
# ---------------------------------------------------------------------------

class TestFindingTimeout:

    @pytest.mark.asyncio
    async def test_timed_out_finding_skipped_cycle_continues(self):
        """A hung finding times out and the cycle continues with the next one."""
        import app.main as main_mod

        findings = _make_findings(3)
        config = _make_config(max_per_cycle=20, timeout_s=0.01)  # 10ms timeout
        processed = []
        call_count = 0

        async def _slow_then_fast(finding, cfg, policies):
            nonlocal call_count
            call_count += 1
            if call_count == 1:
                # First finding hangs
                await asyncio.sleep(10)
            processed.append(finding["finding_id"])

        triage_stub = MagicMock()
        triage_stub.run = AsyncMock(return_value=findings)

        with patch.object(main_mod, "TriageAgent", return_value=triage_stub), \
             patch.object(main_mod, "_process_finding", side_effect=_slow_then_fast), \
             patch.object(main_mod, "_pipeline_sem", None):
            await main_mod.run_remediation_cycle(config)

        # First finding timed out (not in processed), remaining two completed
        assert "finding-0" not in processed
        assert "finding-1" in processed
        assert "finding-2" in processed

    @pytest.mark.asyncio
    async def test_timeout_does_not_leave_semaphore_locked(self):
        """After a timeout the semaphore slot is released (async with guarantees this)."""
        import app.main as main_mod

        findings = _make_findings(2)
        config = _make_config(max_per_cycle=20, timeout_s=0.01)
        processed = []

        async def _slow(finding, cfg, policies):
            if finding["finding_id"] == "finding-0":
                await asyncio.sleep(10)
            else:
                processed.append(finding["finding_id"])

        triage_stub = MagicMock()
        triage_stub.run = AsyncMock(return_value=findings)

        sem = asyncio.Semaphore(1)  # Only 1 slot — ensures slot released after timeout

        with patch.object(main_mod, "TriageAgent", return_value=triage_stub), \
             patch.object(main_mod, "_process_finding", side_effect=_slow), \
             patch.object(main_mod, "_pipeline_sem", sem):
            await main_mod.run_remediation_cycle(config)

        assert "finding-1" in processed
        assert sem._value == 1  # Slot fully released


# ---------------------------------------------------------------------------
# ExecutionConfig defaults
# ---------------------------------------------------------------------------

class TestExecutionConfigDefaults:

    def test_default_max_findings_per_cycle(self):
        from config.schema import ExecutionConfig
        cfg = ExecutionConfig()
        assert cfg.max_findings_per_cycle == 20

    def test_default_finding_timeout_seconds(self):
        from config.schema import ExecutionConfig
        cfg = ExecutionConfig()
        assert cfg.finding_timeout_seconds == 300

    def test_custom_values_accepted(self):
        from config.schema import ExecutionConfig
        cfg = ExecutionConfig(max_findings_per_cycle=5, finding_timeout_seconds=60)
        assert cfg.max_findings_per_cycle == 5
        assert cfg.finding_timeout_seconds == 60
