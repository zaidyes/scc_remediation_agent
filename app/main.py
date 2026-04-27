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
    impact_result = await ImpactAgent(config).analyse(finding)
    dormancy_result = await DormancyAgent(config).check(finding["resource_name"])

    plan = await PlanAgent(config).generate(finding, impact_result, dormancy_result)
    if plan is None:
        print(f"[plan] No applicable remediation mode for {finding['finding_id']} — skipping")
        return

    if plan.get("status") == "BLOCKED":
        print(
            f"[plan] BLOCKED for {finding['finding_id']}: {plan.get('block_reason')} "
            f"— escalating to Tier 3 for human resolution"
        )
        await _dispatch_for_approval(plan, finding, impact_result, config, tier=3)
        return

    blast_level = impact_result.get("blast_level", "HIGH")
    dormancy_class = impact_result.get("dormancy_class", "ACTIVE")

    # Pre-flight results are now embedded in the plan by PlanAgent Phase 1
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
        f"(confidence={confidence}, blast={blast_level})"
    )

    if tier == 1:
        print(f"[tier1] Autonomously executing {finding['finding_id']}")
        await _execute_plan(plan, finding, config)
    elif tier == 2:
        print(f"[tier2] Sending policy-assisted approval card for {finding['finding_id']}")
        await _dispatch_for_approval(plan, finding, impact_result, config, tier=2)
    else:
        print(f"[tier3] Escalating {finding['finding_id']} for expert review")
        await _dispatch_for_approval(plan, finding, impact_result, config, tier=3)


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
        # No policy covers this finding — default to Tier 3
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


async def _execute_plan(plan: dict, finding: dict, config: CustomerConfig) -> None:
    if config.dry_run:
        print(f"[dry-run] Would execute plan {plan['plan_id']} for {finding['finding_id']}")
        return

    remediation_type = plan.get("remediation_type")

    if remediation_type == "OS_PATCH":
        job_name = create_patch_job(
            project_id=_extract_project(finding["resource_name"]),
            asset_name=finding["resource_name"],
            cve_ids=finding.get("cve_ids", []),
            config=config,
        )
        print(f"[execute] Patch job created: {job_name}")
        if job_name:
            result = await VerifyAgent(config).verify(plan)
            print(f"[verify] {result}")
    else:
        # MISCONFIGURATION, IAM, FIREWALL direct execution comes in Phase 2/3
        # (requires rollback artifact creation first). Escalate to Tier 2 for now.
        print(
            f"[execute] {remediation_type} direct execution not yet implemented "
            f"— escalating to Tier 2 approval"
        )
        await _dispatch_for_approval(plan, finding, {}, config, tier=2)


async def _dispatch_for_approval(
    plan: dict,
    finding: dict,
    impact: dict,
    config: CustomerConfig,
    tier: int = 3,
) -> None:
    approval_id = await dispatch_approval_request(
        plan=plan,
        finding=finding,
        impact=impact,
        config=config,
        channels=config.approval_policy.notification_channels,
        tier=tier,
    )
    print(f"[approval] Dispatched Tier {tier} approval request {approval_id}")


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
