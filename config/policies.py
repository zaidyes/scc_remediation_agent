"""
Pydantic models for customer autonomous execution policies.

Policies live in Firestore at:
  /configs/{customer_id}/policies/{policy_id}

They define under what conditions the agent may execute tier 1 or tier 2
remediations without full expert review.
"""
import datetime
from typing import Any, Optional

from pydantic import BaseModel, Field


class LabelCondition(BaseModel):
    key: str
    value: str


class PolicySimulationResult(BaseModel):
    """Stored at policy creation time — shows what would have been executed."""
    findings_evaluated: int
    would_execute_tier1: int
    would_execute_tier2: int
    would_escalate_tier3: int
    edge_cases: list[dict[str, Any]] = Field(default_factory=list)
    # edge_cases: findings inside the policy boundary with amber pre-flight signals
    historical_success_rate: Optional[float] = None
    simulated_at: datetime.datetime = Field(default_factory=datetime.datetime.utcnow)


class ExecutionPolicy(BaseModel):
    """
    A single autonomous execution policy for a customer.

    Tier 1 policies allow the agent to execute without any human approval.
    Tier 2 policies send a single-tap confirm card to the approver.
    """
    policy_id: str
    customer_id: str
    name: str
    description: str = ""

    # --- Matching conditions -------------------------------------------------
    remediation_type: str                    # OS_PATCH | MISCONFIGURATION | IAM | FIREWALL
    severity_levels: list[str]              # e.g. ["LOW", "MEDIUM"]
    finding_categories: list[str] = Field(default_factory=list)
    # empty list = all categories for this remediation type
    asset_label_conditions: list[LabelCondition] = Field(default_factory=list)
    # ALL conditions must match for the policy to apply

    # --- Safety thresholds ---------------------------------------------------
    min_confidence_threshold: float = 0.90
    # Tier 1 minimum is 0.90; floor is 0.80 (enforced in validator)
    max_blast_radius: str = "LOW"            # LOW | MEDIUM

    # --- Policy tier ---------------------------------------------------------
    tier: int = 2                            # 1 = fully autonomous, 2 = single-tap confirm

    # --- Lifecycle -----------------------------------------------------------
    active: bool = True
    created_by: str = ""
    version: int = 1
    created_at: datetime.datetime = Field(default_factory=datetime.datetime.utcnow)
    updated_at: datetime.datetime = Field(default_factory=datetime.datetime.utcnow)

    # Simulation result stored at creation time — required before activation
    simulation_result: Optional[PolicySimulationResult] = None
    # True once the user has explicitly acknowledged edge cases in the simulation
    edge_cases_acknowledged: bool = False

    def matches(self, finding: dict, blast_level: str) -> bool:
        """
        Returns True if this policy applies to the given finding and blast level.
        All conditions must match.
        """
        if not self.active:
            return False

        # Remediation type
        finding_class = finding.get("finding_class", "")
        rem_type = _FINDING_CLASS_TO_REMEDIATION.get(finding_class)
        if rem_type != self.remediation_type:
            return False

        # Severity
        if finding.get("severity") not in self.severity_levels:
            return False

        # Finding category (if specified)
        if self.finding_categories and finding.get("category") not in self.finding_categories:
            return False

        # Blast radius cap
        blast_order = ["LOW", "MEDIUM", "HIGH", "CRITICAL"]
        if blast_order.index(blast_level) > blast_order.index(self.max_blast_radius):
            return False

        # Asset label conditions
        asset_labels = finding.get("resource_labels", {})
        for condition in self.asset_label_conditions:
            if asset_labels.get(condition.key) != condition.value:
                return False

        return True

    class Config:
        use_enum_values = True


_FINDING_CLASS_TO_REMEDIATION: dict[str, str] = {
    "VULNERABILITY": "OS_PATCH",
    "MISCONFIGURATION": "MISCONFIGURATION",
    "IAM_POLICY": "IAM",
    "NETWORK": "FIREWALL",
}
