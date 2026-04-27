import datetime
from enum import Enum
from typing import TYPE_CHECKING, Optional

from pydantic import BaseModel, Field, validator

if TYPE_CHECKING:
    from config.policies import ExecutionPolicy

class SeverityThreshold(str, Enum):
    CRITICAL_ONLY = "CRITICAL_ONLY"
    HIGH_PLUS = "HIGH_PLUS"
    MEDIUM_PLUS = "MEDIUM_PLUS"
    ALL = "ALL"

    def to_api_values(self) -> list[str]:
        mapping = {
            "CRITICAL_ONLY": ["CRITICAL"],
            "HIGH_PLUS": ["CRITICAL", "HIGH"],
            "MEDIUM_PLUS": ["CRITICAL", "HIGH", "MEDIUM"],
            "ALL": ["CRITICAL", "HIGH", "MEDIUM", "LOW"],
        }
        return mapping[self.value]

class RemediationMode(str, Enum):
    OS_PATCH = "OS_PATCH"
    MISCONFIGURATION = "MISCONFIGURATION"
    IAM = "IAM"
    FIREWALL = "FIREWALL"

class LabelFilter(BaseModel):
    key: str
    value: str

class ScopeConfig(BaseModel):
    project_ids: list[str] = Field(default_factory=list)
    folder_ids: list[str] = Field(default_factory=list)
    include_labels: list[LabelFilter] = Field(default_factory=list)
    exclude_labels: list[LabelFilter] = Field(default_factory=list)

    def matches_asset(self, asset: dict) -> bool:
        """Returns True if the asset is within scope."""
        labels = asset.get("labels", {})
        project = asset.get("project", "")

        # Project check (if project_ids specified)
        if self.project_ids and project not in self.project_ids:
            return False

        # Include labels (ALL must match)
        for f in self.include_labels:
            if labels.get(f.key) != f.value:
                return False

        # Exclude labels (ANY match = out of scope)
        for f in self.exclude_labels:
            if labels.get(f.key) == f.value:
                return False

        return True

class FindingFilters(BaseModel):
    require_active_exposure_path: bool = True
    exclude_dormant_assets: bool = False
    deduplicate_across_scanners: bool = True
    exclude_accepted_risks: bool = True

class Approver(BaseModel):
    name: str
    type: str                               # "email" | "group" | "label_resolved"
    address: str                            # email, group address, or label key
    severity_levels: list[str]              # which severities they approve
    channel: str                            # "chat" | "pagerduty" | "jira"
    fallback_address: Optional[str] = None

class ApprovalTier(BaseModel):
    name: str
    condition: dict                         # severity + env conditions
    requires_approval: bool
    auto_approve_eligible: bool
    grace_period_minutes: int = 30
    escalate_after_minutes: int = 15

class MaintenanceWindow(BaseModel):
    days_of_week: list[int]                 # 0=Mon, 6=Sun
    start_time_utc: str                     # HH:MM
    end_time_utc: str
    timezone: str = "UTC"

class ApprovalPolicy(BaseModel):
    tiers: list[ApprovalTier]
    approvers: list[Approver]
    default_maintenance_window: MaintenanceWindow
    auto_approve_enabled: bool = True
    notification_channels: list[str] = Field(default_factory=list)

class ExecutionConfig(BaseModel):
    enabled_modes: list[RemediationMode] = Field(default_factory=list)
    max_blast_radius_for_auto: int = 5      # max downstream deps for auto-approve
    gitops_repo: Optional[str] = None       # for Terraform PR mode
    gitops_branch: str = "main"

class NotificationConfig(BaseModel):
    google_chat_space: Optional[str] = None
    pagerduty_service_key: Optional[str] = None
    jira_project_key: Optional[str] = None
    jira_base_url: Optional[str] = None
    email_digest_recipients: list[str] = Field(default_factory=list)

class CustomerConfig(BaseModel):
    customer_id: str
    org_id: str
    display_name: str = ""
    version: int = 1
    created_at: datetime.datetime = Field(default_factory=datetime.datetime.utcnow)
    updated_at: datetime.datetime = Field(default_factory=datetime.datetime.utcnow)
    updated_by: str = ""
    dry_run: bool = True                    # Default: safe mode
    scope: ScopeConfig
    severity_threshold: SeverityThreshold = SeverityThreshold.HIGH_PLUS
    filters: FindingFilters = Field(default_factory=FindingFilters)
    approval_policy: ApprovalPolicy
    execution: ExecutionConfig = Field(default_factory=ExecutionConfig)
    notifications: NotificationConfig = Field(default_factory=NotificationConfig)
    # Autonomous execution policies — empty list means all findings go to Tier 3
    policies: list[dict] = Field(default_factory=list)
    # Using list[dict] instead of list[ExecutionPolicy] to avoid circular import;
    # app/main.py coerces these to ExecutionPolicy objects at runtime.

    class Config:
        use_enum_values = True
