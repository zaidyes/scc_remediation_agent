"""
Main orchestration loop for the SCC Remediation Agent.

Called on schedule (Cloud Scheduler → Cloud Tasks) or via Pub/Sub trigger
when a new SCC finding notification arrives. Not the ADK entrypoint —
see app/agent.py for the interactive ADK agent.
"""
import argparse
import asyncio
import os

from google.cloud import firestore

from app.agents.triage_agent import TriageAgent
from app.agents.impact_agent import ImpactAgent
from app.agents.dormancy_agent import DormancyAgent
from app.agents.plan_agent import PlanAgent
from app.agents.verify_agent import VerifyAgent
from app.hooks import fire
import app.hooks as hooks
from app.tools.agent_output import compact_impact_for_approval, compact_impact_for_scoring
from app.tools.approval_tools import dispatch_approval_request
from app.tools.confidence import compute_confidence_score
from app.tools.osconfig_tools import create_patch_job
from config.policies import ExecutionPolicy
from config.schema import CustomerConfig
from scheduler.freeze import is_change_frozen


async def run_remediation_cycle(config: CustomerConfig) -> None:
    """Main orchestration loop. Called on schedule or Pub/Sub trigger."""
    print(f"[cycle] Starting remediation cycle for customer {config.customer_id}")

    policies = [ExecutionPolicy(**p) for p in config.policies]

    triage = TriageAgent(config)
    prioritised_findings = await triage.run()
    print(f"[triage] {len(prioritised_findings)} findings in scope after filtering")

    for finding in prioritised_findings:
        print(
            f"[finding] Processing {finding['finding_id']} "
            f"({finding['severity']}) on {finding['resource_name']}"
        )
        await _process_finding(finding, config, policies)


async def _process_finding(
    finding: dict,
    config: CustomerConfig,
    policies: list[ExecutionPolicy],
) -> None:
    base_ctx = {
        "customer_id": config.customer_id,
        "finding_id":  finding["finding_id"],
        "finding":     finding,
        "config":      config,
    }

    ctx = await fire(hooks.PRE_FINDING, {**base_ctx})
    if ctx.get("stop"):
        print(f"[hooks] PRE_FINDING stopped processing {finding['finding_id']}: {ctx.get('stop_reason', '')}")
        return

    # ── Impact + dormancy ────────────────────────────────────────────────────
    await fire(hooks.PRE_IMPACT, {**base_ctx})
    impact_result   = await ImpactAgent(config).analyse(finding)
    dormancy_result = await DormancyAgent(config).check(finding["resource_name"])
    await fire(hooks.POST_IMPACT, {**base_ctx, "impact": impact_result, "dormancy": dormancy_result})

    # ── Plan generation ──────────────────────────────────────────────────────
    await fire(hooks.PRE_PLAN, {**base_ctx})
    plan = await PlanAgent(config).generate(finding, impact_result, dormancy_result)

    if plan is None:
        print(f"[plan] No applicable remediation mode for {finding['finding_id']} — skipping")
        await fire(hooks.POST_FINDING, {**base_ctx, "outcome": "no_plan"})
        return

    if plan.get("status") == "BLOCKED":
        print(
            f"[plan] BLOCKED for {finding['finding_id']}: {plan.get('block_reason')} "
            f"— escalating to Tier 3 for human resolution"
        )
        await fire(hooks.ON_BLOCK, {**base_ctx, "plan": plan, "block_reason": plan.get("block_reason")})
        await _dispatch_for_approval(plan, finding, impact_result, config, tier=3)
        await fire(hooks.POST_FINDING, {**base_ctx, "outcome": "blocked"})
        return

    await fire(hooks.POST_PLAN, {**base_ctx, "plan": plan, "plan_id": plan.get("plan_id")})

    # ── Confidence scoring ───────────────────────────────────────────────────
    scoring_impact  = compact_impact_for_scoring(impact_result)
    blast_level     = scoring_impact.get("blast_level", "HIGH")
    dormancy_class  = dormancy_result.get("dormancy_class", scoring_impact.get("dormancy_class", "ACTIVE"))
    preflight_results: list[dict] = plan.get("preflight_results", [])

    historical_outcomes = await _get_historical_outcomes(
        config.customer_id,
        finding.get("finding_class", ""),
        plan.get("remediation_type", ""),
    )
    confidence = compute_confidence_score(
        preflight_results=preflight_results,
        blast_level=blast_level,
        dormancy_class=dormancy_class,
        historical_outcomes=historical_outcomes,
        finding_class=finding.get("finding_class", ""),
    )
    plan["confidence_score"] = confidence

    # ── Tier decision ────────────────────────────────────────────────────────
    await fire(hooks.PRE_TIER_DECISION, {**base_ctx, "plan": plan, "confidence": confidence})
    tier = _determine_execution_tier(
        finding=finding,
        blast_level=blast_level,
        confidence=confidence,
        preflight_results=preflight_results,
        policies=policies,
        config=config,
    )
    print(
        f"[tier] Finding {finding['finding_id']} → Tier {tier} "
        f"(confidence={confidence:.0%}, blast={blast_level})"
    )
    await fire(hooks.POST_TIER_DECISION, {**base_ctx, "plan": plan, "tier": tier, "confidence": confidence})

    # ── Dispatch ─────────────────────────────────────────────────────────────
    if tier == 1:
        if config.dry_run:
            await fire(hooks.ON_DRY_RUN, {**base_ctx, "plan": plan, "tier": tier})
            print(f"[dry-run] Would execute Tier 1 plan {plan['plan_id']} for {finding['finding_id']}")
        else:
            print(f"[tier1] Autonomously executing {finding['finding_id']}")
            await _execute_plan(plan, finding, config)
    elif tier == 2:
        print(f"[tier2] Sending policy-assisted approval card for {finding['finding_id']}")
        await _dispatch_for_approval(plan, finding, impact_result, config, tier=2)
    else:
        print(f"[tier3] Escalating {finding['finding_id']} for expert review")
        await _dispatch_for_approval(plan, finding, impact_result, config, tier=3)

    await fire(hooks.POST_FINDING, {**base_ctx, "plan": plan, "tier": tier, "outcome": "dispatched"})


def _determine_execution_tier(
    finding: dict,
    blast_level: str,
    confidence: float,
    preflight_results: list[dict],
    policies: list[ExecutionPolicy],
    config: CustomerConfig,
) -> int:
    """
    Returns the execution tier (1, 2, or 3) for a finding.

    Tier 1 — autonomous execution (no human approval)
    Tier 2 — policy-assisted single-tap confirm
    Tier 3 — expert review (default)
    """
    # Hard Tier 3 conditions — checked first
    if config.dry_run:
        return 3

    has_block = any(r.get("result") == "BLOCK" for r in preflight_results)
    if has_block:
        return 3

    if blast_level in ("HIGH", "CRITICAL"):
        return 3

    if confidence < 0.70:
        return 3

    if is_change_frozen(finding["resource_name"], config):
        return 3

    # Find the highest-priority matching policy
    matching_policy = _find_matching_policy(finding, blast_level, policies)
    if matching_policy is None:
        return 3

    warn_count = sum(1 for r in preflight_results if r.get("result") == "WARN")

    # Tier 1 — all pre-flights pass, confidence above threshold, blast is LOW
    if (
        matching_policy.tier == 1
        and warn_count == 0
        and blast_level == "LOW"
        and confidence >= matching_policy.min_confidence_threshold
    ):
        return 1

    # Tier 2 — pre-flights passed (warns OK), blast is LOW or MEDIUM,
    # confidence ≥ 0.70 but below Tier 1 threshold, or exactly one WARN
    if (
        matching_policy.tier <= 2
        and blast_level in ("LOW", "MEDIUM")
        and confidence >= 0.70
        and warn_count <= 1
    ):
        return 2

    return 3


def _find_matching_policy(
    finding: dict,
    blast_level: str,
    policies: list[ExecutionPolicy],
) -> ExecutionPolicy | None:
    """Returns the first active policy whose conditions match the finding."""
    for policy in policies:
        if policy.matches(finding, blast_level):
            return policy
    return None


async def _execute_plan(
    plan: dict,
    finding: dict,
    config: CustomerConfig,
    approval_id: str | None = None,
) -> None:
    """
    Executes a remediation plan step by step.

    Each step passes through the PRE_STEP hook before execution.
    PRE_STEP re-checks change freeze and approval liveness on every step —
    mirroring the per-action permission gate in the Claude Code harness.
    If PRE_STEP sets stop=True the execution loop halts immediately.
    """
    if config.dry_run:
        print(f"[dry-run] Would execute plan {plan['plan_id']} for {finding['finding_id']}")
        return

    base_ctx = {
        "customer_id": config.customer_id,
        "finding_id":  finding["finding_id"],
        "plan_id":     plan.get("plan_id"),
        "finding":     finding,
        "plan":        plan,
        "config":      config,
        "approval_id": approval_id,
    }

    await fire(hooks.PRE_EXECUTE, {**base_ctx})

    remediation_type = plan.get("remediation_type")
    steps = plan.get("steps", [])
    steps_completed = 0

    if remediation_type == "OS_PATCH":
        # OS_PATCH is a single atomic operation (patch job)
        steps = steps or [{"order": 1, "action": "create_patch_job", "command": ""}]

    for step in steps:
        # ── Per-step permission gate ─────────────────────────────────────
        step_ctx = await fire(
            hooks.PRE_STEP,
            {**base_ctx, "step": step, "steps_completed": steps_completed},
        )
        if step_ctx.get("stop"):
            reason = step_ctx.get("stop_reason", "hook_stopped")
            print(
                f"[execute] PRE_STEP halted execution at step "
                f"{step.get('order', steps_completed + 1)}: {reason}"
            )
            await fire(hooks.ON_STEP_FAILURE, {
                **base_ctx,
                "step": step,
                "steps_completed": steps_completed,
                "error": reason,
            })
            await fire(hooks.POST_EXECUTE, {**base_ctx, "steps_completed": steps_completed, "halted": True})
            return

        # ── Execute the step ─────────────────────────────────────────────
        try:
            if remediation_type == "OS_PATCH":
                job_name = create_patch_job(
                    project_id=_extract_project(finding["resource_name"]),
                    asset_name=finding["resource_name"],
                    cve_ids=finding.get("cve_ids", []),
                    config=config,
                )
                step_result = {"job_name": job_name, "status": "submitted"}
                print(f"[execute] Patch job created: {job_name}")
            else:
                # MISCONFIGURATION, IAM, FIREWALL — steps are structured commands
                # from plan["steps"]; executor dispatches by step["action"]
                step_result = await _dispatch_step(step, finding, config)

            steps_completed += 1
            await fire(hooks.POST_STEP, {**base_ctx, "step": step, "result": step_result})

        except Exception as exc:
            print(f"[execute] Step {step.get('order', '?')} failed: {exc}")
            await fire(hooks.ON_STEP_FAILURE, {
                **base_ctx,
                "step": step,
                "steps_completed": steps_completed,
                "error": str(exc),
            })
            await fire(hooks.POST_EXECUTE, {**base_ctx, "steps_completed": steps_completed, "halted": True})
            return

    # ── Verification ─────────────────────────────────────────────────────
    await fire(hooks.PRE_VERIFY, {**base_ctx, "steps_completed": steps_completed})
    try:
        verify_result = await VerifyAgent(config).verify(plan)
        print(f"[verify] {verify_result}")
        await fire(hooks.POST_VERIFY, {**base_ctx, "verify_result": verify_result, "steps_completed": steps_completed})
    except Exception as exc:
        print(f"[verify] Verification failed: {exc}")
        await fire(hooks.ON_VERIFY_FAILURE, {**base_ctx, "error": str(exc), "steps_completed": steps_completed})

    await fire(hooks.POST_EXECUTE, {**base_ctx, "steps_completed": steps_completed, "halted": False})


async def _dispatch_step(step: dict, finding: dict, config: CustomerConfig) -> dict:
    """
    Dispatches a single structured remediation step.
    Called for FIREWALL, IAM, and MISCONFIGURATION plan steps.
    Steps contain: order, action, command (gcloud / API call), rollback_command.
    """
    action = step.get("action", "")
    command = step.get("command", "")

    if not command:
        print(f"[execute] Step {step.get('order', '?')}: no command specified — skipping")
        return {"status": "skipped", "reason": "no_command"}

    import subprocess
    result = subprocess.run(
        command,
        shell=True,
        capture_output=True,
        text=True,
        timeout=120,
    )
    if result.returncode != 0:
        raise RuntimeError(f"Step '{action}' failed (rc={result.returncode}): {result.stderr[:500]}")

    return {"status": "success", "stdout": result.stdout[:500], "returncode": result.returncode}


async def _dispatch_for_approval(
    plan: dict,
    finding: dict,
    impact: dict,
    config: CustomerConfig,
    tier: int = 3,
) -> None:
    base_ctx = {
        "customer_id": config.customer_id,
        "finding_id":  finding["finding_id"],
        "finding":     finding,
        "plan":        plan,
        "plan_id":     plan.get("plan_id"),
        "config":      config,
        "tier":        tier,
    }

    ctx = await fire(hooks.PRE_APPROVAL_DISPATCH, {**base_ctx})
    if ctx.get("stop"):
        print(f"[hooks] PRE_APPROVAL_DISPATCH stopped dispatch: {ctx.get('stop_reason', '')}")
        return

    approval_id = await dispatch_approval_request(
        plan=plan,
        finding=finding,
        impact=compact_impact_for_approval(impact),
        config=config,
        channels=config.approval_policy.notification_channels,
        tier=tier,
    )
    print(f"[approval] Dispatched Tier {tier} approval request {approval_id}")
    await fire(hooks.POST_APPROVAL_DISPATCH, {**base_ctx, "approval_id": approval_id})


async def _get_historical_outcomes(
    customer_id: str,
    finding_class: str,
    remediation_type: str,
    limit: int = 50,
) -> list[dict]:
    """
    Fetches recent remediation outcomes from the audit log for confidence scoring.
    Returns a list of {"outcome": "SUCCESS"|"FAILURE"} dicts.
    """
    try:
        db = firestore.AsyncClient()
        query = (
            db.collection("audit_log")
            .where("customer_id", "==", customer_id)
            .where("remediation_type", "==", remediation_type)
            .where("event_type", "in", ["VERIFICATION_SUCCESS", "VERIFICATION_FAILED"])
            .order_by("timestamp", direction=firestore.Query.DESCENDING)
            .limit(limit)
        )
        docs = await query.get()
        return [
            {
                "outcome": "SUCCESS"
                if doc.get("event_type") == "VERIFICATION_SUCCESS"
                else "FAILURE"
            }
            for doc in docs
        ]
    except Exception:
        return []


def _extract_project(resource_name: str) -> str:
    parts = resource_name.split("/")
    if "projects" in parts:
        return parts[parts.index("projects") + 1]
    return ""


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="SCC Remediation Agent batch cycle")
    parser.add_argument("--customer-id", default=os.environ.get("CUSTOMER_ID"))
    args = parser.parse_args()

    if not args.customer_id:
        raise SystemExit("customer_id is required (--customer-id or CUSTOMER_ID env var)")

    db = firestore.Client()
    doc = db.collection("customer_configs").document(args.customer_id).get()
    if not doc.exists:
        raise SystemExit(f"No config found for customer_id={args.customer_id}")

    config = CustomerConfig(**doc.to_dict())
    asyncio.run(run_remediation_cycle(config))
