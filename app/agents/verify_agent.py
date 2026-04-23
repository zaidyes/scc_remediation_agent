import asyncio

from app.tools.scc_tools import get_finding_detail, mute_resolved_finding
from app.tools.graph_tools import update_resource_finding_state


class VerifyAgent:
    def __init__(self, config):
        self.config = config

    async def verify(
        self,
        plan: dict,
        max_retries: int = 6,
        retry_interval_seconds: int = 300,
    ) -> dict:
        """
        Polls SCC until the finding is no longer ACTIVE, or max_retries is exhausted.
        On success: updates the graph, mutes the finding (unless dry_run), returns success dict.
        On failure: returns escalation_required=True for manual follow-up.
        """
        finding_id = plan["finding_id"]
        asset_name = plan["asset_name"]

        for attempt in range(max_retries):
            await asyncio.sleep(retry_interval_seconds if attempt > 0 else 60)

            finding = get_finding_detail(finding_id, self.config.org_id)
            state = finding.get("state", "ACTIVE")

            if state != "ACTIVE":
                update_resource_finding_state(
                    asset_name=asset_name,
                    finding_id=finding_id,
                    new_state="REMEDIATED",
                )
                if not self.config.dry_run:
                    mute_resolved_finding(finding_id, self.config.org_id)

                return {
                    "success": True,
                    "final_state": state,
                    "attempts": attempt + 1,
                }

        return {
            "success": False,
            "final_state": "ACTIVE",
            "attempts": max_retries,
            "escalation_required": True,
        }
