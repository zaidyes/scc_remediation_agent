"""
Main orchestration loop for the SCC Remediation Agent.

Called on schedule (Cloud Scheduler → Cloud Tasks) or via Pub/Sub trigger
when a new SCC finding notification arrives. Not the ADK entrypoint —
see app/agent.py for the interactive ADK agent.
"""
import asyncio
import os

from app.agents.triage_agent import TriageAgent
from app.agents.impact_agent import ImpactAgent
from app.agents.dormancy_agent import DormancyAgent
from app.agents.plan_agent import PlanAgent
from app.agents.verify_agent import VerifyAgent
from app.tools.approval_tools import dispatch_approval_request
from app.tools.osconfig_tools import create_patch_job
from config.schema import CustomerConfig
from scheduler.freeze import is_change_frozen


async def run_remediation_cycle(config: CustomerConfig) -> None:
    """
    Main orchestration loop. Called on schedule or Pub/Sub trigger.
    """
    print(f"[cycle] Starting remediation cycle for customer {config.customer_id}")

    triage = TriageAgent(config)
    prioritised_findings = await triage.run()
    print(f"[triage] {len(prioritised_findings)} findings in scope after filtering")

    for finding in prioritised_findings:
        print(
            f"[finding] Processing {finding['finding_id']} "
            f"({finding['severity']}) on {finding['resource_name']}"
        )
        await _process_finding(finding, config)


async def _process_finding(finding: dict, config: CustomerConfig) -> None:
    impact_result = await ImpactAgent(config).analyse(finding)
    dormancy_result = await DormancyAgent(config).check(finding["resource_name"])

    plan = await PlanAgent(config).generate(finding, impact_result, dormancy_result)
    if plan is None:
        print(f"[plan] No applicable remediation mode for {finding['finding_id']} — skipping")
        return

    if _is_auto_approve_eligible(finding, impact_result, dormancy_result, config):
        print(f"[approve] Auto-approving {finding['finding_id']}")
        await _execute_plan(plan, finding, config)
    else:
        await _dispatch_for_approval(plan, finding, impact_result, config)


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
        # MISCONFIGURATION and IAM execution are dispatched for human approval
        # regardless of auto-approve eligibility — direct execution not yet implemented
        print(f"[execute] Remediation type {remediation_type} requires manual execution")


async def _dispatch_for_approval(
    plan: dict,
    finding: dict,
    impact: dict,
    config: CustomerConfig,
) -> None:
    approval_id = await dispatch_approval_request(
        plan=plan,
        finding=finding,
        impact=impact,
        config=config,
        channels=config.approval_policy.notification_channels,
    )
    print(f"[approval] Dispatched approval request {approval_id}")


def _is_auto_approve_eligible(
    finding: dict,
    impact: dict,
    dormancy: dict,
    config: CustomerConfig,
) -> bool:
    """
    Returns True only when ALL of:
    - dry_run is False
    - auto_approve_enabled is True
    - blast radius is LOW (zero prod downstream dependencies)
    - asset is DORMANT or PERIODIC (not actively serving traffic)
    - no change freeze is active on the resource or its project
    """
    if config.dry_run:
        return False
    if not config.approval_policy.auto_approve_enabled:
        return False
    if impact.get("prod_blast_count", 0) > 0:
        return False
    if dormancy.get("dormancy_class") == "ACTIVE":
        return False
    if is_change_frozen(finding["resource_name"], config):
        return False
    return True


def _extract_project(resource_name: str) -> str:
    parts = resource_name.split("/")
    if "projects" in parts:
        return parts[parts.index("projects") + 1]
    return ""


if __name__ == "__main__":
    from google.cloud import firestore

    customer_id = os.environ["CUSTOMER_ID"]
    db = firestore.Client()
    doc = db.collection("configs").document(customer_id).get()
    if not doc.exists:
        raise SystemExit(f"No config found for customer_id={customer_id}")

    config = CustomerConfig(**doc.to_dict())
    asyncio.run(run_remediation_cycle(config))
