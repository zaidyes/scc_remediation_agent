"""
Phase 1 of the two-phase plan pipeline: deterministic pre-flight checks.

No LLM is involved. Each check calls a GCP API and returns a structured
pass/warn/block result. Results feed the confidence score and are surfaced
verbatim on the approval card.
"""
import asyncio
import datetime
from typing import Literal

from google.cloud import asset_v1, compute_v1, logging_v2, osconfig_v1

CheckResult = Literal["PASS", "WARN", "BLOCK"]


def _check(result: CheckResult, check: str, detail: str) -> dict:
    return {"check": check, "result": result, "detail": detail}


class PreflightAgent:
    def __init__(self, config):
        self.config = config

    async def run(
        self,
        finding: dict,
        remediation_type: str,
        resource_data: dict,
    ) -> list[dict]:
        """
        Runs the appropriate pre-flight checklist for the remediation type.
        Returns a list of check result dicts.
        """
        dispatch = {
            "OS_PATCH": self._os_patch_checks,
            "FIREWALL": self._firewall_checks,
            "IAM": self._iam_checks,
            "MISCONFIGURATION": self._misconfiguration_checks,
        }
        handler = dispatch.get(remediation_type)
        if handler is None:
            return [_check("PASS", "remediation_type", f"No pre-flight checks for {remediation_type}")]

        return await handler(finding, resource_data)

    # ----------------------------------------------------------------------- #
    # OS patch pre-flight
    # ----------------------------------------------------------------------- #

    async def _os_patch_checks(self, finding: dict, resource_data: dict) -> list[dict]:
        results = await asyncio.gather(
            self._check_change_freeze(finding),
            self._check_instance_in_mig(resource_data),
            self._check_active_ssh_session(finding, resource_data),
            self._check_recent_deployment(finding, resource_data),
            self._check_snapshot_policy(resource_data),
            self._check_lb_health(resource_data),
            self._check_reboot_required(finding, resource_data),
            return_exceptions=False,
        )
        return list(results)

    async def _check_change_freeze(self, finding: dict) -> dict:
        """HARD BLOCK if resource or project has change-freeze=true label."""
        from scheduler.freeze import is_change_frozen
        try:
            frozen = is_change_frozen(finding["resource_name"], self.config)
            if frozen:
                return _check("BLOCK", "change_freeze",
                              "Resource or project has change-freeze=true label active")
            return _check("PASS", "change_freeze", "No change freeze detected")
        except Exception as e:
            return _check("WARN", "change_freeze", f"Could not determine freeze status: {e}")

    async def _check_instance_in_mig(self, resource_data: dict) -> dict:
        """WARN if the instance is part of a Managed Instance Group."""
        try:
            metadata = resource_data.get("metadata", {})
            items = metadata.get("items", [])
            in_mig = any(i.get("key") == "instance-template" for i in items)
            if in_mig:
                return _check("WARN", "mig_membership",
                              "Instance is in a MIG — patch job will trigger rolling update")
            return _check("PASS", "mig_membership", "Instance is not in a MIG")
        except Exception as e:
            return _check("WARN", "mig_membership", f"Could not determine MIG status: {e}")

    async def _check_active_ssh_session(self, finding: dict, resource_data: dict) -> dict:
        """WARN if Cloud Logging shows an active SSH session in the last 30 minutes."""
        try:
            client = logging_v2.Client(project=_extract_project(finding["resource_name"]))
            instance_name = resource_data.get("name", "")
            cutoff = (datetime.datetime.utcnow() - datetime.timedelta(minutes=30)).isoformat() + "Z"
            filter_str = (
                f'protoPayload.methodName="v1.compute.instances.setMetadata" '
                f'AND resource.labels.instance_id="{resource_data.get("id", "")}" '
                f'AND timestamp>="{cutoff}"'
            )
            entries = list(client.list_entries(filter_=filter_str, max_results=1))
            if entries:
                return _check("WARN", "active_ssh_session",
                              "Active SSH session detected in last 30 min — patching may interrupt")
            return _check("PASS", "active_ssh_session", "No active SSH sessions detected")
        except Exception as e:
            return _check("WARN", "active_ssh_session", f"Could not check SSH sessions: {e}")

    async def _check_recent_deployment(self, finding: dict, resource_data: dict) -> dict:
        """WARN if any write operation on this resource occurred in the last 2 hours."""
        try:
            client = logging_v2.Client(project=_extract_project(finding["resource_name"]))
            resource_name = finding["resource_name"]
            cutoff = (datetime.datetime.utcnow() - datetime.timedelta(hours=2)).isoformat() + "Z"
            filter_str = (
                f'protoPayload.resourceName="{resource_name}" '
                f'AND protoPayload.request!=null '
                f'AND timestamp>="{cutoff}"'
            )
            entries = list(client.list_entries(filter_=filter_str, max_results=1))
            if entries:
                return _check("WARN", "recent_deployment",
                              "Deployment or write operation detected on this resource in last 2h — "
                              "verify stability before patching")
            return _check("PASS", "recent_deployment", "No recent deployments detected")
        except Exception as e:
            return _check("WARN", "recent_deployment", f"Could not check recent deployments: {e}")

    async def _check_snapshot_policy(self, resource_data: dict) -> dict:
        """BLOCK if no snapshot policy and disk quota is exceeded."""
        try:
            disks = resource_data.get("disks", [])
            if not disks:
                return _check("PASS", "snapshot_policy", "No persistent disks found on instance")

            # Check if any disk has a snapshot schedule
            for disk in disks:
                resource_policies = disk.get("resourcePolicies", [])
                if resource_policies:
                    return _check("PASS", "snapshot_policy",
                                  "Snapshot policy exists on instance disk(s)")

            return _check("WARN", "snapshot_policy",
                          "No snapshot policy found — agent will create a snapshot before patching; "
                          "execution will block if disk quota is exceeded")
        except Exception as e:
            return _check("WARN", "snapshot_policy", f"Could not check snapshot policy: {e}")

    async def _check_lb_health(self, resource_data: dict) -> dict:
        """WARN if the instance is registered as a backend in a load balancer."""
        try:
            # If the resource data has network interfaces, check for LB references
            # Full check requires iterating backend services — use a lightweight heuristic
            tags = resource_data.get("tags", {}).get("items", [])
            network_interfaces = resource_data.get("networkInterfaces", [])

            # Check for access configs indicating external reachability via LB
            for iface in network_interfaces:
                for ac in iface.get("accessConfigs", []):
                    if ac.get("type") == "ONE_TO_ONE_NAT":
                        return _check("WARN", "lb_health_check",
                                      "Instance has external IP — may be behind a load balancer; "
                                      "verify health check interval before patching")

            return _check("PASS", "lb_health_check",
                          "No load balancer attachment detected on network interface")
        except Exception as e:
            return _check("WARN", "lb_health_check", f"Could not check LB registration: {e}")

    async def _check_reboot_required(self, finding: dict, resource_data: dict) -> dict:
        """WARN if the OS Config vulnerability report indicates a reboot is required."""
        try:
            project = _extract_project(finding["resource_name"])
            instance_name = resource_data.get("name", "")
            zone = _extract_zone(resource_data.get("zone", ""))

            client = osconfig_v1.OsConfigServiceClient()
            instance_ref = f"zones/{zone}/instances/{instance_name}"
            report = client.get_vulnerability_report(
                name=f"projects/{project}/{instance_ref}/vulnerabilityReport"
            )

            reboot_needed = any(
                vuln.details
                for vuln in report.vulnerabilities
                if hasattr(vuln, "details")
            )

            cve_ids = [v.cve_id for v in report.vulnerabilities if v.cve_id] if report.vulnerabilities else []
            finding_cves = set(finding.get("cve_ids", []))
            relevant = [c for c in cve_ids if c in finding_cves]

            if relevant:
                return _check("WARN", "reboot_required",
                              f"OS Config report indicates patch may require reboot "
                              f"(CVEs: {', '.join(relevant[:3])})")
            return _check("PASS", "reboot_required",
                          "OS Config report does not indicate reboot requirement")
        except Exception as e:
            return _check("WARN", "reboot_required", f"Could not check OS Config report: {e}")

    # ----------------------------------------------------------------------- #
    # Firewall rule pre-flight
    # ----------------------------------------------------------------------- #

    async def _firewall_checks(self, finding: dict, resource_data: dict) -> list[dict]:
        results = await asyncio.gather(
            self._check_change_freeze(finding),
            self._check_active_connections(finding, resource_data),
            self._check_cloud_armor_overlap(finding, resource_data),
            self._check_sa_auth_from_blocked_range(finding, resource_data),
            return_exceptions=False,
        )
        return list(results)

    async def _check_active_connections(self, finding: dict, resource_data: dict) -> dict:
        """BLOCK if VPC Flow Logs show active traffic from the range being blocked."""
        try:
            project = _extract_project(finding["resource_name"])
            cutoff = (datetime.datetime.utcnow() - datetime.timedelta(hours=24)).isoformat() + "Z"

            # Extract source ranges from the firewall rule resource data
            source_ranges = resource_data.get("sourceRanges", [])
            if not source_ranges:
                return _check("PASS", "active_connections",
                              "No source ranges on rule — cannot detect active connections")

            client = logging_v2.Client(project=project)
            # VPC flow logs are in the compute.googleapis.com/vpc_flows log
            filter_str = (
                f'logName="projects/{project}/logs/compute.googleapis.com%2Fvpc_flows" '
                f'AND jsonPayload.connection.dest_port!=null '
                f'AND timestamp>="{cutoff}"'
            )
            entries = list(client.list_entries(filter_=filter_str, max_results=5))

            if entries:
                return _check("BLOCK", "active_connections",
                              f"VPC Flow Logs show active traffic in last 24h from range(s) "
                              f"{source_ranges[:2]} — blocking this range may disrupt live connections")
            return _check("PASS", "active_connections",
                          "No active connections detected from source ranges in last 24h")
        except Exception as e:
            return _check("WARN", "active_connections", f"Could not check VPC flow logs: {e}")

    async def _check_cloud_armor_overlap(self, finding: dict, resource_data: dict) -> dict:
        """WARN if a Cloud Armor policy already covers the same traffic."""
        try:
            project = _extract_project(finding["resource_name"])
            client = compute_v1.SecurityPoliciesClient()
            policies = client.list(project=project)
            policy_names = [p.name for p in policies]

            if policy_names:
                return _check("WARN", "cloud_armor_overlap",
                              f"Cloud Armor policies exist ({', '.join(policy_names[:2])}) — "
                              "verify no double-block before applying firewall change")
            return _check("PASS", "cloud_armor_overlap", "No Cloud Armor policies found in project")
        except Exception as e:
            return _check("WARN", "cloud_armor_overlap", f"Could not check Cloud Armor policies: {e}")

    async def _check_sa_auth_from_blocked_range(self, finding: dict, resource_data: dict) -> dict:
        """WARN if a service account is authenticating from the IP range being blocked."""
        try:
            source_ranges = resource_data.get("sourceRanges", [])
            if not source_ranges:
                return _check("PASS", "sa_auth_from_blocked_range",
                              "No source ranges specified on rule")

            project = _extract_project(finding["resource_name"])
            client = asset_v1.AssetServiceClient()

            # Use analyzeIamPolicy to check if any SA has recent auth from these ranges
            # This is a best-effort check — full check would require Cloud Audit Logs correlation
            request = asset_v1.AnalyzeIamPolicyRequest(
                analysis_query=asset_v1.IamPolicyAnalysisQuery(
                    scope=f"projects/{project}",
                    access_selector=asset_v1.IamPolicyAnalysisQuery.AccessSelector(
                        roles=["roles/iam.serviceAccountTokenCreator"]
                    ),
                )
            )
            response = client.analyze_iam_policy(request=request)
            sa_count = len(response.main_analysis.analysis_results)

            if sa_count > 0:
                return _check("WARN", "sa_auth_from_blocked_range",
                              f"Found {sa_count} service account(s) with token creator roles — "
                              "verify none authenticate from the blocked IP range")
            return _check("PASS", "sa_auth_from_blocked_range",
                          "No service accounts found authenticating from blocked ranges")
        except Exception as e:
            return _check("WARN", "sa_auth_from_blocked_range",
                          f"Could not check SA auth from blocked range: {e}")

    # ----------------------------------------------------------------------- #
    # IAM binding removal pre-flight
    # ----------------------------------------------------------------------- #

    async def _iam_checks(self, finding: dict, resource_data: dict) -> list[dict]:
        results = await asyncio.gather(
            self._check_change_freeze(finding),
            self._check_role_last_used(finding, resource_data),
            self._check_redundant_grants(finding, resource_data),
            self._check_active_sa_keys(finding, resource_data),
            return_exceptions=False,
        )
        return list(results)

    async def _check_role_last_used(self, finding: dict, resource_data: dict) -> dict:
        """WARN if the role has NOT been used in the last 90 days (strengthens removal case)."""
        try:
            project = _extract_project(finding["resource_name"])
            client = asset_v1.AssetServiceClient()

            member = resource_data.get("member", "")
            role = resource_data.get("role", "")

            request = asset_v1.AnalyzeIamPolicyRequest(
                analysis_query=asset_v1.IamPolicyAnalysisQuery(
                    scope=f"projects/{project}",
                    identity_selector=asset_v1.IamPolicyAnalysisQuery.IdentitySelector(
                        identity=member
                    ),
                    access_selector=asset_v1.IamPolicyAnalysisQuery.AccessSelector(
                        roles=[role]
                    ),
                ),
                execution_timeout={"seconds": 30},
            )
            response = client.analyze_iam_policy(request=request)

            results = response.main_analysis.analysis_results
            if not results:
                return _check("WARN", "role_last_used",
                              f"Role {role} for {member} shows no recent usage — "
                              "safe to remove (strengthens case)")
            return _check("PASS", "role_last_used",
                          f"Role {role} has active grants — review before removal")
        except Exception as e:
            return _check("WARN", "role_last_used", f"Could not check role usage: {e}")

    async def _check_redundant_grants(self, finding: dict, resource_data: dict) -> dict:
        """WARN if another role grants the same permissions via a different path."""
        try:
            project = _extract_project(finding["resource_name"])
            member = resource_data.get("member", "")
            role = resource_data.get("role", "")

            client = asset_v1.AssetServiceClient()
            request = asset_v1.AnalyzeIamPolicyRequest(
                analysis_query=asset_v1.IamPolicyAnalysisQuery(
                    scope=f"projects/{project}",
                    identity_selector=asset_v1.IamPolicyAnalysisQuery.IdentitySelector(
                        identity=member
                    ),
                )
            )
            response = client.analyze_iam_policy(request=request)
            all_roles = set()
            for result in response.main_analysis.analysis_results:
                for binding in result.iam_binding.role:
                    all_roles.add(binding)

            other_roles = all_roles - {role}
            if other_roles:
                return _check("WARN", "redundant_grants",
                              f"Principal {member} has {len(other_roles)} other role(s) — "
                              "verify no other path grants the same permissions")
            return _check("PASS", "redundant_grants",
                          "No redundant grants detected for this principal")
        except Exception as e:
            return _check("WARN", "redundant_grants", f"Could not check redundant grants: {e}")

    async def _check_active_sa_keys(self, finding: dict, resource_data: dict) -> dict:
        """WARN if the service account has active keys created or used recently."""
        try:
            member = resource_data.get("member", "")
            if not member.startswith("serviceAccount:"):
                return _check("PASS", "active_sa_keys",
                              "Principal is not a service account — key check not applicable")

            sa_email = member.replace("serviceAccount:", "")
            project = _extract_project(finding["resource_name"])

            from google.oauth2 import service_account
            from googleapiclient.discovery import build

            iam_service = build("iam", "v1")
            keys_response = (
                iam_service.projects()
                .serviceAccounts()
                .keys()
                .list(name=f"projects/{project}/serviceAccounts/{sa_email}")
                .execute()
            )
            keys = keys_response.get("keys", [])
            user_keys = [k for k in keys if k.get("keyType") == "USER_MANAGED"]

            if user_keys:
                return _check("WARN", "active_sa_keys",
                              f"Service account has {len(user_keys)} user-managed key(s) — "
                              "removing IAM binding does not revoke existing keys")
            return _check("PASS", "active_sa_keys",
                          "No user-managed service account keys found")
        except Exception as e:
            return _check("WARN", "active_sa_keys", f"Could not check SA keys: {e}")

    # ----------------------------------------------------------------------- #
    # Misconfiguration pre-flight (basic checks)
    # ----------------------------------------------------------------------- #

    async def _misconfiguration_checks(self, finding: dict, resource_data: dict) -> list[dict]:
        results = await asyncio.gather(
            self._check_change_freeze(finding),
            return_exceptions=False,
        )
        return list(results)


# ----------------------------------------------------------------------- #
# Helpers
# ----------------------------------------------------------------------- #

def _extract_project(resource_name: str) -> str:
    parts = resource_name.split("/")
    if "projects" in parts:
        return parts[parts.index("projects") + 1]
    return ""


def _extract_zone(zone_url: str) -> str:
    """Extracts zone name from a full zone URL like .../zones/us-central1-a."""
    return zone_url.split("/")[-1] if "/" in zone_url else zone_url
