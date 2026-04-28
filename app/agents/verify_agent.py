"""
Type-specific post-remediation verification + 30-minute regression monitor.

Replaces the generic SCC re-query with checks that are faster and more
authoritative for each remediation type:

  OS_PATCH     → OS Config vulnerability report (CVE no longer listed)
  FIREWALL     → Network Intelligence Center Connectivity Test
  IAM          → Cloud Asset analyzeIamPolicy (permission no longer granted)
  MISC/default → SCC finding state fallback
"""
import asyncio
import uuid

from google.cloud import asset_v1, network_management_v1, osconfig_v1
from google.cloud.network_management_v1 import ConnectivityTest, Endpoint

from app.tools.agent_output import compact_plan_for_verify
from app.tools.scc_tools import get_finding_detail, mute_resolved_finding
from app.tools.graph_tools import update_resource_finding_state
from app.tools.regression_monitor import monitor_for_regression


class VerifyAgent:
    def __init__(self, config):
        self.config = config

    async def verify(self, plan: dict) -> dict:
        """
        Runs type-specific verification, then launches the regression monitor
        as a background task. Returns immediately after verification is confirmed.
        """
        # Compact to only the fields this agent actually reads — strips steps,
        # rollback_steps, preflight_results, confidence_score, summary, etc.
        plan = compact_plan_for_verify(plan)
        remediation_type = plan.get("remediation_type", "")

        dispatch = {
            "OS_PATCH": self._verify_os_patch,
            "FIREWALL": self._verify_firewall,
            "IAM": self._verify_iam,
        }
        handler = dispatch.get(remediation_type, self._verify_scc_fallback)
        result = await handler(plan)

        if result.get("success"):
            # Update graph state
            update_resource_finding_state(
                asset_name=plan["asset_name"],
                finding_id=plan["finding_id"],
                new_state="REMEDIATED",
            )

            # Mute the SCC finding
            if not self.config.dry_run:
                mute_resolved_finding(plan["finding_id"], self.config.org_id)

            # Launch regression monitor as a background task — does not block
            blast_radius_assets = plan.get("blast_radius_assets", [])
            plan_with_approval = {**plan, "project_id": _extract_project(plan["asset_name"])}
            asyncio.create_task(
                monitor_for_regression(
                    plan=plan_with_approval,
                    blast_radius_assets=blast_radius_assets,
                )
            )

        return result

    # ----------------------------------------------------------------------- #
    # OS patch verification
    # ----------------------------------------------------------------------- #

    async def _verify_os_patch(
        self,
        plan: dict,
        max_retries: int = 6,
        retry_interval_seconds: int = 300,
    ) -> dict:
        """
        Queries the OS Config vulnerability report for the specific instance
        and confirms the CVE is no longer listed. Faster and more authoritative
        than waiting for SCC to update.
        """
        project = _extract_project(plan["asset_name"])
        instance_name = plan["asset_name"].split("/")[-1]
        zone = _extract_segment(plan["asset_name"], "zones")
        target_cves = set(plan.get("cve_ids", []))

        client = osconfig_v1.OsConfigServiceClient()
        report_name = (
            f"projects/{project}/locations/{zone}/instances/{instance_name}"
            f"/vulnerabilityReport"
        )

        for attempt in range(max_retries):
            if attempt > 0:
                await asyncio.sleep(retry_interval_seconds)

            try:
                report = client.get_vulnerability_report(name=report_name)
                remaining_cves = {
                    v.cve_id
                    for v in report.vulnerabilities
                    if v.cve_id and v.cve_id in target_cves
                }

                if not remaining_cves:
                    return {
                        "success": True,
                        "verification_type": "OS_CONFIG_VULN_REPORT",
                        "detail": f"All target CVEs cleared from OS Config report",
                        "attempts": attempt + 1,
                    }

            except Exception as e:
                if attempt == max_retries - 1:
                    return {
                        "success": False,
                        "verification_type": "OS_CONFIG_VULN_REPORT",
                        "detail": f"OS Config report check failed: {e}",
                        "attempts": max_retries,
                        "escalation_required": True,
                    }

        return {
            "success": False,
            "verification_type": "OS_CONFIG_VULN_REPORT",
            "detail": f"CVEs still present in OS Config report after {max_retries} checks",
            "attempts": max_retries,
            "escalation_required": True,
        }

    # ----------------------------------------------------------------------- #
    # Firewall rule verification
    # ----------------------------------------------------------------------- #

    async def _verify_firewall(self, plan: dict) -> dict:
        """
        Uses NIC Connectivity Test to verify that intended traffic paths still
        work after the firewall rule change.
        """
        project = _extract_project(plan["asset_name"])
        test_cases = plan.get("connectivity_test_cases", [])

        if not test_cases:
            # No test cases specified — fall back to SCC check
            return await self._verify_scc_fallback(plan)

        client = network_management_v1.ReachabilityServiceClient()
        results = []

        for case in test_cases:
            test_id = f"scc-verify-{uuid.uuid4().hex[:8]}"
            test = ConnectivityTest(
                name=f"projects/{project}/locations/global/connectivityTests/{test_id}",
                source=Endpoint(
                    ip_address=case.get("source_ip"),
                    project_id=project,
                ),
                destination=Endpoint(
                    ip_address=case.get("dest_ip"),
                    port=case.get("dest_port", 443),
                    project_id=project,
                ),
                protocol=case.get("protocol", "TCP"),
            )

            try:
                operation = client.create_connectivity_test(
                    parent=f"projects/{project}/locations/global",
                    connectivity_test_id=test_id,
                    resource=test,
                )
                completed_test = operation.result(timeout=120)
                reachability = (
                    completed_test.reachability_details.result
                    if completed_test.reachability_details
                    else "UNKNOWN"
                )
                results.append({
                    "case": case,
                    "reachability": str(reachability),
                    "passed": str(reachability) in (
                        "REACHABLE", "ReachabilityDetails.Result.REACHABLE"
                    ),
                })

                # Clean up test resource
                client.delete_connectivity_test(
                    name=f"projects/{project}/locations/global/connectivityTests/{test_id}"
                )

            except Exception as e:
                results.append({"case": case, "reachability": "ERROR", "error": str(e),
                                 "passed": False})

        all_passed = all(r["passed"] for r in results)
        return {
            "success": all_passed,
            "verification_type": "CONNECTIVITY_TEST",
            "detail": f"{sum(r['passed'] for r in results)}/{len(results)} connectivity tests passed",
            "test_results": results,
            "escalation_required": not all_passed,
        }

    # ----------------------------------------------------------------------- #
    # IAM verification
    # ----------------------------------------------------------------------- #

    async def _verify_iam(self, plan: dict) -> dict:
        """
        Runs analyzeIamPolicy to confirm the principal can no longer access
        the resource via the removed role, and that no other role grants the
        same permission via a different path.
        """
        project = _extract_project(plan["asset_name"])
        member = plan.get("iam_member")
        role = plan.get("iam_role")

        if not member or not role:
            return await self._verify_scc_fallback(plan)

        try:
            client = asset_v1.AssetServiceClient()
            request = asset_v1.AnalyzeIamPolicyRequest(
                analysis_query=asset_v1.IamPolicyAnalysisQuery(
                    scope=f"projects/{project}",
                    identity_selector=asset_v1.IamPolicyAnalysisQuery.IdentitySelector(
                        identity=member
                    ),
                    resource_selector=asset_v1.IamPolicyAnalysisQuery.ResourceSelector(
                        full_resource_name=plan["asset_name"]
                    ),
                    access_selector=asset_v1.IamPolicyAnalysisQuery.AccessSelector(
                        roles=[role]
                    ),
                )
            )
            response = client.analyze_iam_policy(request=request)
            remaining_grants = response.main_analysis.analysis_results

            if not remaining_grants:
                return {
                    "success": True,
                    "verification_type": "IAM_POLICY_ANALYSIS",
                    "detail": (
                        f"Confirmed: {member} can no longer access {plan['asset_name']} "
                        f"via {role} or any equivalent path"
                    ),
                }

            # Role still exists via another path
            paths = [str(r) for r in remaining_grants[:3]]
            return {
                "success": False,
                "verification_type": "IAM_POLICY_ANALYSIS",
                "detail": (
                    f"Principal {member} still has access via {len(remaining_grants)} "
                    f"alternative grant(s) — manual review required"
                ),
                "remaining_grants": paths,
                "escalation_required": True,
            }

        except Exception as e:
            return {
                "success": False,
                "verification_type": "IAM_POLICY_ANALYSIS",
                "detail": f"analyzeIamPolicy failed: {e}",
                "escalation_required": True,
            }

    # ----------------------------------------------------------------------- #
    # SCC fallback (used for MISCONFIGURATION and on API errors)
    # ----------------------------------------------------------------------- #

    async def _verify_scc_fallback(
        self,
        plan: dict,
        max_retries: int = 6,
        retry_interval_seconds: int = 300,
    ) -> dict:
        """Polls SCC finding state until INACTIVE or retries exhausted."""
        finding_id = plan["finding_id"]

        for attempt in range(max_retries):
            if attempt > 0:
                await asyncio.sleep(retry_interval_seconds)

            try:
                finding = get_finding_detail(finding_id, self.config.org_id)
                state = finding.get("state", "ACTIVE")
                if state != "ACTIVE":
                    return {
                        "success": True,
                        "verification_type": "SCC_FINDING_STATE",
                        "detail": f"SCC finding state changed to {state}",
                        "attempts": attempt + 1,
                    }
            except Exception:
                pass

        return {
            "success": False,
            "verification_type": "SCC_FINDING_STATE",
            "detail": f"Finding still ACTIVE after {max_retries} checks",
            "attempts": max_retries,
            "escalation_required": True,
        }


# --------------------------------------------------------------------------- #
# Helpers
# --------------------------------------------------------------------------- #

def _extract_project(asset_name: str) -> str:
    parts = asset_name.replace("//", "").split("/")
    if "projects" in parts:
        return parts[parts.index("projects") + 1]
    return ""


def _extract_segment(asset_name: str, segment: str) -> str:
    parts = asset_name.replace("//", "").split("/")
    if segment in parts:
        return parts[parts.index(segment) + 1]
    return ""
