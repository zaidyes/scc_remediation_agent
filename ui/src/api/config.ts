const BASE = "/api";

async function request<T>(path: string, options?: RequestInit): Promise<T> {
  const res = await fetch(`${BASE}${path}`, {
    headers: { "Content-Type": "application/json" },
    ...options,
  });
  if (!res.ok) {
    const err = await res.json().catch(() => ({ detail: res.statusText }));
    throw new Error(err.detail ?? `HTTP ${res.status}`);
  }
  return res.json();
}

// ----- Config -----

export const getConfig = (customerId: string) =>
  request<CustomerConfig>(`/config/${customerId}`);

export const saveConfig = (customerId: string, config: Partial<CustomerConfig>) =>
  request<{ version: number }>(`/config/${customerId}`, {
    method: "PUT",
    body: JSON.stringify(config),
  });

export const listVersions = (customerId: string) =>
  request<{ version: number; updated_at: string }[]>(`/config/${customerId}/versions`);

export const validateConfig = (config: Partial<CustomerConfig>) =>
  request<ValidationResult>("/config/validate", {
    method: "POST",
    body: JSON.stringify(config),
  });

export const previewScope = (scope: ScopeConfig) =>
  request<{ asset_count: number; filter_description: string }>("/config/preview-scope", {
    method: "POST",
    body: JSON.stringify({ scope }),
  });

export const simulate = (config: Partial<CustomerConfig>) =>
  request<SimulationResult>("/config/simulate", {
    method: "POST",
    body: JSON.stringify(config),
  });

// ----- Findings -----

export const getActiveFindings = (customerId: string, limit = 50) =>
  request<{ findings: Finding[]; total: number }>(
    `/findings/active?customer_id=${customerId}&limit=${limit}`
  );

// ----- Approvals -----

export const getPendingApprovals = (customerId: string) =>
  request<{ approvals: Approval[] }>(`/approvals/pending?customer_id=${customerId}`);

export const respondToApproval = (
  approvalId: string,
  action: "APPROVED" | "REJECTED" | "DEFERRED",
  responderEmail: string
) =>
  request<{ status: string }>(`/approval/${approvalId}/respond`, {
    method: "POST",
    body: JSON.stringify({ action, responder_email: responderEmail }),
  });

// ----- Audit -----

export const getAuditLog = (customerId: string, limit = 50, pageToken?: string) =>
  request<{ entries: AuditEntry[]; next_page_token: string | null }>(
    `/audit?customer_id=${customerId}&limit=${limit}${pageToken ? `&page_token=${pageToken}` : ""}`
  );

// ----- Rollback -----

export const rollbackApproval = (approvalId: string) =>
  request<{ status: string; output?: string }>(`/rollback/${approvalId}`, {
    method: "POST",
  });

// ----- Policies -----

export const getPolicies = (customerId: string) =>
  request<ExecutionPolicy[]>(`/policies/${customerId}`);

export const upsertPolicy = (customerId: string, policy: ExecutionPolicy) =>
  request<ExecutionPolicy>(`/policies/${customerId}`, {
    method: "POST",
    body: JSON.stringify(policy),
  });

export const deletePolicy = (customerId: string, policyId: string) =>
  request<{ deleted: boolean }>(`/policies/${customerId}/${policyId}`, {
    method: "DELETE",
  });

export const simulatePolicy = (customerId: string, policyId: string) =>
  request<PolicySimulationResult>(`/policies/${customerId}/${policyId}/simulate`, {
    method: "POST",
  });

// ----- Types -----

export interface LabelFilter { key: string; value: string }

export interface ScopeConfig {
  project_ids: string[];
  folder_ids: string[];
  include_labels: LabelFilter[];
  exclude_labels: LabelFilter[];
}

export interface MaintenanceWindow {
  days_of_week: number[];
  start_time_utc: string;
  end_time_utc: string;
  timezone: string;
}

export interface Approver {
  name: string;
  type: string;
  address: string;
  severity_levels: string[];
  channel: string;
  fallback_address?: string;
}

export interface ApprovalTier {
  name: string;
  condition: Record<string, string[]>;
  requires_approval: boolean;
  auto_approve_eligible: boolean;
  grace_period_minutes: number;
  escalate_after_minutes: number;
}

export interface ApprovalPolicy {
  tiers: ApprovalTier[];
  approvers: Approver[];
  default_maintenance_window: MaintenanceWindow;
  auto_approve_enabled: boolean;
  notification_channels: string[];
}

export interface ExecutionConfig {
  enabled_modes: string[];
  max_blast_radius_for_auto: number;
  gitops_repo?: string;
  gitops_branch: string;
}

export interface NotificationConfig {
  google_chat_space?: string;
  pagerduty_service_key?: string;
  jira_project_key?: string;
  jira_base_url?: string;
  email_digest_recipients: string[];
}

export interface CustomerConfig {
  customer_id: string;
  org_id: string;
  display_name: string;
  version: number;
  dry_run: boolean;
  scope: ScopeConfig;
  severity_threshold: string;
  approval_policy: ApprovalPolicy;
  execution: ExecutionConfig;
  notifications: NotificationConfig;
  updated_at?: string;
}

export interface Finding {
  finding_id: string;
  resource_name: string;
  short_name: string;
  category: string;
  severity: string;
  finding_class: string;
  blast_level?: string;
  attack_exposure_score: number;
  state: string;
  agent_status: string;
  event_time: string;
  plan_id?: string;
}

export interface Approval {
  approval_id: string;
  finding_id: string;
  asset_name: string;
  severity: string;
  blast_level: string;
  plan_summary: string;
  status: string;
  created_at: string;
  expires_at: string;
  channels_notified: string[];
  escalation_count: number;
}

export interface AuditEntry {
  entry_id: string;
  event_type: string;
  finding_id?: string;
  asset_name?: string;
  detail: string;
  actor: string;
  timestamp: string;
}

export interface ValidationResult {
  valid: boolean;
  errors: string[];
  warnings: string[];
  preview: {
    assets_in_scope: number;
    active_findings_in_scope: number;
    estimated_auto_approve: number;
    dry_run_active: boolean;
  };
}

export interface SimulationResult extends ValidationResult {
  approver_routing: { name: string; address: string; severities: string[] }[];
  auto_approve_conditions: {
    enabled: boolean;
    max_blast_radius: number;
    dry_run_active: boolean;
  };
}

export interface ExecutionPolicy {
  policy_id: string;
  customer_id: string;
  remediation_type: string;
  severity_levels: string[];
  finding_categories: string[];
  asset_label_conditions: Record<string, string>;
  min_confidence_threshold: number;
  max_blast_radius: string;
  tier: 1 | 2;
  active: boolean;
}

export interface PolicySimulationResult {
  findings_evaluated: number;
  would_execute_tier1: number;
  would_execute_tier2: number;
  would_execute_tier3: number;
  edge_cases: string[];
}
