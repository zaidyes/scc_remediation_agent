# SCC Remediation Agent — Architecture Addendum

> **Document purpose:** This addendum captures all design decisions, architectural
> changes, and new components agreed after the main spec (v1.1) was written.
> A coding agent should read the main spec first, then apply every override and
> addition in this document. Where this document conflicts with the main spec,
> this document takes precedence.
>
> **Main spec version this addendum applies to:** v1.1
> **Addendum version:** 1.0.0
> **Last updated:** 2026-04-25

---

## Table of contents

1. [Remediation intelligence overhaul](#1-remediation-intelligence-overhaul)
2. [Policy-based autonomous execution tiers](#2-policy-based-autonomous-execution-tiers)
3. [Graph freshness: event-driven over surgical refresh](#3-graph-freshness-event-driven-over-surgical-refresh)
4. [Change event filter pipeline](#4-change-event-filter-pipeline)
5. [Proximity index](#5-proximity-index)
6. [Tiered invalidation response](#6-tiered-invalidation-response)
7. [Repository additions](#7-repository-additions)
8. [Infrastructure additions](#8-infrastructure-additions)
9. [Revised open questions](#9-revised-open-questions)

---

## 1. Remediation intelligence overhaul

### 1.1 What changed and why

The main spec describes the agent primarily as a triage and prioritisation tool
with remediation execution bolted on. This framing is wrong. Triage is a solved
problem — SCC itself does reasonable triage and many vendors offer prioritised
finding lists. The differentiation is in **remediation intelligence**: the ability
to answer the four questions that come after "should I fix this?":

1. Is it actually safe to apply this fix right now?
2. What exactly will break if I do?
3. What does "fixed" look like for this specific resource in this specific config?
4. Did the fix work, and did it cause anything else to break?

The plan agent in the main spec generates generic remediation guidance. This must
be replaced with a two-phase system.

### 1.2 Plan agent: two-phase replacement

**Replace** the single `plan_agent.py` with a two-phase pipeline:

#### Phase 1 — Pre-flight checks (deterministic, no LLM)

Pre-flight checks run before plan generation. They are deterministic GCP API calls
with binary pass/fail/warn outputs. The LLM is not involved. Results are stored as
structured data and surfaced in the approval card.

Pre-flight checks are specific to remediation type:

**OS patch pre-flight checklist:**

| Check | API | Pass condition | Fail action |
|---|---|---|---|
| Instance in MIG? | Compute API `instances.get` → check `metadata.items` for `instance-template` | Not in MIG, or MIG has rolling update policy | WARN: "Instance is in MIG — patch job will trigger rolling update" |
| Active SSH session? | Cloud Logging — filter `protoPayload.methodName="v1.compute.instances.setMetadata"` last 30 min | No active sessions | WARN: "Active SSH session detected — patching may interrupt" |
| Recent deployment? | Cloud Audit Logs — any write operation on this resource last 2 hours | No deployment in last 2 hours | WARN: "Deployment detected in last 2h — verify stability before patching" |
| Snapshot policy exists? | OS Config API | Snapshot policy exists OR can be created | BLOCK if quota exceeded and no snapshot exists |
| Load balancer health check? | Compute API — check backend services | No LB pointing at instance, or health check interval > patch duration | WARN: "LB health check active — instance may be briefly removed from pool" |
| Patch requires reboot? | OS Config vulnerability report | `rollout.disruptionBudget` acceptable | WARN if reboot required |
| Change freeze active? | Resource labels + Firestore config | `change-freeze != true` | HARD BLOCK |

**Firewall rule pre-flight checklist:**

| Check | API | Pass condition | Fail action |
|---|---|---|---|
| Active connections from blocked range? | VPC Flow Logs — last 24h | Zero flow log entries from IPs being blocked | BLOCK if active traffic detected |
| Cloud Armor already handles this? | Compute API security policies | No duplicate rule at higher layer | WARN: "Cloud Armor policy may already cover this — verify no double-block" |
| SA authenticating from blocked range? | Policy Analyser | No SA using blocked IP range | WARN |

**IAM binding removal pre-flight checklist:**

| Check | API | Pass condition | Fail action |
|---|---|---|---|
| Role used in last 90 days? | IAM Recommender / Policy Analyser last-used data | Role has been used | WARN if unused — strengthens case for removal |
| Other resources affected? | Policy Analyser `analyzeIamPolicy` | No other resources grant same permissions via different path | WARN if redundant grant exists |
| Active service account keys? | IAM API `projects.serviceAccounts.keys.list` | No active keys, or keys last used > 90 days | WARN |

Pre-flight results feed directly into the confidence score (see section 2.2).

#### Phase 2 — Configuration-specific plan generation (LLM)

**Replace** the generic prompt template in `plan_agent.py` with one that passes
the full resource data blob from Asset Inventory alongside pre-flight results.

The `resource.data` field in Asset Inventory contains the complete REST
representation of the resource — all current flags, all current config. Pass
this to Gemini so the generated plan is specific to this resource's actual
configuration, not a generic pattern.

Key rule: **if any pre-flight check returns BLOCK, the LLM generates a blocked
plan with explanation — it does not attempt to work around the blocker.**

Updated prompt template context:

```
## Pre-flight results
{preflight_json}           # structured pass/warn/block results

## Full resource data (live from Asset Inventory)
{resource_data_json}       # complete resource.data blob

## Finding
{finding_json}

## Graph context (blast radius, IAM paths, dormancy)
{impact_json}

## SCC remediation guidance
{remediation_text}

## Instructions
Generate a remediation plan specific to THIS resource's current configuration.
Reference actual disk names, zones, service account emails, and flags from the
resource data. If any pre-flight check returned BLOCK, set plan status to
BLOCKED and explain why. Include exact gcloud commands or API calls, not
generic patterns. Include a machine-executable rollback artifact.
```

### 1.3 Rollback as a first-class engineering artifact

**Replace** the text-description rollback in the main spec with machine-executable
rollback artifacts stored alongside every approval record.

Rules per remediation type:

- **OS patch:** before executing, create an instance snapshot via Compute API.
  Store snapshot name and `gcloud compute disks create --source-snapshot` restore
  command in Firestore on the approval record. If snapshot creation fails (quota,
  disk size), this is a BLOCK condition unless the human explicitly overrides.

- **Firewall rule change:** before applying, export the current rule to GCS as
  JSON (`gcloud compute firewall-rules export`). Store the restore command
  (`gcloud compute firewall-rules import`) on the approval record.

- **IAM binding removal:** store the exact `gcloud projects add-iam-policy-binding`
  restore command on the approval record before removing the binding.

- **Misconfiguration (Terraform PR):** the PR itself is the rollback artifact —
  reverting the PR restores the prior state. Store the PR URL and revert command
  on the approval record.

One-click rollback must be available from the approval card for 24 hours after
execution. The rollback button calls a `/api/rollback/{approval_id}` endpoint
that executes the stored restore command.

### 1.4 Post-fix validation: replace SCC re-query with type-specific checks

**Replace** the single SCC re-query in `verify_agent.py` with type-specific
validation plus a regression monitor.

**OS patch:** query the OS Config vulnerability report for the specific instance
and confirm the CVE is no longer listed. This is faster and more authoritative
than waiting for SCC to update.

**Firewall rule change:** use Network Intelligence Center Connectivity Test API
to verify that intended traffic paths still work after the rule change. Call
`networkmanagement.connectivityTests.create` with the specific source/destination
pairs that the rule change was meant to affect.

**IAM binding removal:** run `cloudasset.analyzeIamPolicy` to confirm the
principal can no longer access the resource. Verify no other role grants the
same permission via a different path.

**Regression monitor (all types):** for 30 minutes after any change, monitor
Cloud Logging error rates on the affected resource and all resources in its
blast radius. If error rate increases more than 2 standard deviations above the
7-day baseline, trigger automatic rollback and alert the approver.

```python
# agent/agents/verify_agent.py — add regression monitor

async def monitor_for_regression(
    plan: dict,
    blast_radius_assets: list[str],
    monitor_duration_minutes: int = 30,
    check_interval_seconds: int = 60,
) -> dict:
    """
    Monitors error rates on the target and blast radius assets.
    Triggers rollback if regression detected.
    Returns final status.
    """
    from google.cloud import monitoring_v3
    import datetime, asyncio, statistics

    client = monitoring_v3.MetricServiceClient()
    project_id = plan["project_id"]
    assets_to_monitor = [plan["asset_name"]] + blast_radius_assets[:10]

    baseline = await _get_error_rate_baseline(client, project_id, assets_to_monitor)
    checks = monitor_duration_minutes * 60 // check_interval_seconds

    for _ in range(checks):
        await asyncio.sleep(check_interval_seconds)
        current = await _get_current_error_rate(client, project_id, assets_to_monitor)

        for asset, rate in current.items():
            b = baseline.get(asset, {})
            mean = b.get("mean", 0)
            std = b.get("std", 0)
            if std > 0 and rate > mean + (2 * std):
                # Regression detected — trigger rollback
                await _execute_rollback(plan)
                return {
                    "status": "REGRESSION_DETECTED",
                    "asset": asset,
                    "current_rate": rate,
                    "baseline_mean": mean,
                    "rollback_triggered": True,
                }

    return {"status": "STABLE", "rollback_triggered": False}
```

---

## 2. Policy-based autonomous execution tiers

### 2.1 Why this matters

The main spec uses a binary human-in-the-loop model: every finding goes through
an approval workflow. This does not scale. In large environments with hundreds
of findings per day, every finding requiring individual human approval creates a
bottleneck that defeats the purpose of the agent.

The solution is to move human oversight to the **policy level** rather than the
**individual finding level**. Humans write policies once; the agent executes all
conforming cases autonomously; humans only see exceptions.

### 2.2 Three execution tiers

**Replace** the single approval workflow in section 8 of the main spec with a
three-tier execution model.

#### Tier 1 — Autonomous execution

No human approval required. Agent executes and sends a notification (not a
request). The daily digest shows what was done.

Conditions (ALL must be true):
- Finding severity and type match a customer-defined autonomous execution policy
- All pre-flight checks passed (no WARN or BLOCK)
- Blast radius is LOW (zero prod downstream dependencies)
- Confidence score ≥ customer-configured threshold (default: 0.90)
- Change freeze is not active
- Dry-run mode is disabled
- Rollback artifact successfully created and stored

#### Tier 2 — Policy-assisted approval

Human confirms the agent's recommendation — they are not making the decision,
they are validating it. The approval card says "we believe this is safe, here
is the evidence" rather than "should we do this?"

Conditions:
- Pre-flight checks all passed
- Blast radius is LOW or MEDIUM
- Confidence score between 0.70 and 0.90, OR one WARN pre-flight result
- Remediation type is in scope for Tier 2 per policy

The approval card for Tier 2 is a single-tap confirm. It shows the pre-flight
checklist, the confidence score, and the rollback artifact. Default timeout:
4 hours, then auto-escalate to Tier 3.

#### Tier 3 — Expert review

Human makes the decision. Full context provided. Agent has prepared everything
but will not proceed without explicit approval.

Conditions:
- Any BLOCK pre-flight result (hard requirement — always Tier 3)
- Blast radius HIGH or CRITICAL
- Confidence score below 0.70
- Novel configuration not seen before in this environment
- Conflict with another pending change detected
- Any HARD_BLOCK from the invalidation system (section 6)

### 2.3 Confidence score

The confidence score (0.0–1.0) is computed per finding and stored on the plan.

```python
def compute_confidence_score(
    preflight_results: list[dict],
    blast_level: str,
    dormancy_class: str,
    historical_outcomes: list[dict],
    finding_class: str,
) -> float:
    """
    Returns a confidence score 0.0–1.0 representing how safe it is
    to execute this remediation autonomously.
    """
    score = 1.0

    # Pre-flight penalties
    block_count = sum(1 for r in preflight_results if r["result"] == "BLOCK")
    warn_count = sum(1 for r in preflight_results if r["result"] == "WARN")
    if block_count > 0:
        return 0.0  # hard floor — any block = zero confidence
    score -= warn_count * 0.15  # each warning reduces confidence by 15%

    # Blast radius penalties
    blast_penalties = {"LOW": 0.0, "MEDIUM": 0.15, "HIGH": 0.40, "CRITICAL": 0.70}
    score -= blast_penalties.get(blast_level, 0.40)

    # Dormancy bonus — dormant resources are lower risk to change
    if dormancy_class == "DORMANT":
        score = min(1.0, score + 0.10)

    # Historical outcomes — weight by similar fixes in this environment
    if historical_outcomes:
        success_rate = sum(
            1 for o in historical_outcomes if o.get("outcome") == "SUCCESS"
        ) / len(historical_outcomes)
        # Blend: 70% rule-based score, 30% historical
        score = (score * 0.70) + (success_rate * 0.30)

    return round(max(0.0, min(1.0, score)), 3)
```

### 2.4 Policy authoring

Add a policy authoring workflow to the Config UI (new step after step 4 in the
5-step wizard, or a separate "Policies" page in the dashboard).

When a customer defines a new autonomous execution policy, the UI must:

1. **Simulate** the policy against the last 30 days of findings and show exactly
   which ones would have been autonomously executed
2. **Surface edge cases** — findings that fall inside the policy boundary but have
   amber pre-flight signals
3. **Show historical outcomes** for similar fixes in this environment
4. **Require explicit acknowledgement** of any edge cases before the policy
   activates
5. **Store the policy with version history** — same append-only pattern as the
   main config

Add `policies` collection to Firestore:

```
/configs/{customer_id}/policies/{policy_id}
  remediation_type: string
  severity_levels: [string]
  finding_categories: [string]
  asset_label_conditions: [{key, value}]
  min_confidence_threshold: float
  max_blast_radius: string    # LOW | MEDIUM
  tier: int                   # 1 | 2
  active: bool
  created_by: string
  version: int
  simulation_result: {...}    # stored at creation time
```

---

## 3. Graph freshness: event-driven over surgical refresh

### 3.1 Decision

**Replace** the surgical refresh approach described in the previous conversation
with an event-driven graph update architecture as the primary freshness mechanism.

**Rationale:** Surgical refresh solves staleness reactively — you discover the
graph is stale at the worst possible moment (immediately before execution) and
then decide whether to abort. Event-driven keeps the graph current continuously.
By the time execution fires, the graph is already accurate. Abort-on-stale
becomes a safety net for edge cases rather than a routine code path.

The surgical refresh code does not disappear entirely. It is retained as a
**final safety check immediately before execution**, but its scope is narrow:
check whether the approval record has any unacknowledged WARN or BLOCK flags
from the invalidation system. This is a single Firestore read, not a multi-API
round-trip.

### 3.2 CAI feeds setup

**Add** `infrastructure/setup_feeds.py` to the repository. This runs once during
agent onboarding. It creates three Cloud Asset Inventory feeds at org level,
all publishing to Pub/Sub:

| Feed ID | Content type | Asset types | Topic |
|---|---|---|---|
| `scc-agent-resource-changes` | RESOURCE | All compute, storage, GKE, run, functions, SA, project types | `asset-change-events` |
| `scc-agent-iam-changes` | IAM_POLICY | Compute instance, bucket, BQ dataset, cluster, project, SA | `asset-change-events` |
| `scc-agent-relationship-changes` | RELATIONSHIP | Instance, network, subnetwork, cluster — network interface, subnetwork, SA attachment types only | `asset-change-events` |

**Add** a Cloud Logging sink that exports material audit events to a second
Pub/Sub topic `audit-change-events`. Filter:

```
resource.type="gce_instance"
AND (
  protoPayload.methodName="v1.compute.instances.setIamPolicy"
  OR protoPayload.methodName="v1.compute.instances.start"
  OR protoPayload.methodName="v1.compute.instances.stop"
  OR protoPayload.methodName="beta.compute.instances.setMetadata"
  OR protoPayload.methodName="v1.compute.firewalls.patch"
  OR protoPayload.methodName="v1.compute.firewalls.insert"
  OR protoPayload.methodName="v1.compute.firewalls.delete"
)
OR (
  resource.type="service_account"
  AND protoPayload.methodName:"SetIamPolicy"
)
OR (
  protoPayload.methodName="SetIamPolicy"
  AND protoPayload.resourceName=~"projects/.*"
)
```

### 3.3 Event processor service

**Add** `graph/events/processor.py` as a new Cloud Run service with two
Pub/Sub push subscription endpoints:

- `POST /events/asset` — receives CAI feed events
- `POST /events/audit` — receives Cloud Audit Log events

The processor:
1. Decodes the Pub/Sub message
2. Passes the event through the filter pipeline (section 4)
3. If material: updates the graph
4. If material: calls the proximity index to find affected approvals
5. If approvals affected: runs the tiered invalidation response (section 6)

This service must be **idempotent** — Pub/Sub delivers at-least-once. Use the
Pub/Sub message ID as an idempotency key stored in Firestore
(`/processed_events/{message_id}`) with a 24-hour TTL.

### 3.4 Background full sync retained as reconciliation

The 6-hour full sync from the main spec is **retained but repurposed**. It is
no longer the primary update mechanism. Its job is reconciliation: catch any
events the Pub/Sub stream missed due to delivery failures, CAI eventual
consistency lag, or feed outages. It does not replace any data that the event
processor has already updated more recently (compare `last_synced` timestamps
before overwriting).

---

## 4. Change event filter pipeline

### 4.1 Purpose

In large environments, CAI feeds can produce thousands of events per hour. The
vast majority are irrelevant to any pending remediation. Without filtering,
the invalidation system produces constant noise and approvals become unusable.

The filter pipeline runs on **every incoming event before any graph or approval
logic is touched**. It must be fast — no database calls, no API calls. Pure
in-memory logic on the event payload.

### 4.2 Three filter stages

**Stage 1 — Change type significance.**

Only the following change types can affect remediation safety. All other events
are discarded immediately:

```python
MATERIAL_CHANGE_TYPES = {
    "IAM_POLICY",           # always material
    "status_change",        # RUNNING → STOPPED / TERMINATED / DELETED
    "deletion",             # resource no longer exists
    "firewall_rule_change", # affects network-adjacent remediations
    "network_interface_change",
    "service_account_change",
    "critical_label_change", # ONLY if env=, change-freeze=, owner=, or maint-window= changed
}
```

For `IAM_POLICY` events: check whether IAM bindings actually changed by
comparing binding content (not just the etag). CAI sends IAM_POLICY events
on etag refreshes where bindings are identical. These must be discarded.

For `RESOURCE` events: compare `resource.data.status`, critical label keys,
and service account attachment against `priorAsset`. If nothing in those
fields changed, discard.

**Stage 2 — Remediation type relevance matrix.**

Not all change types affect all remediation types. A firewall change cannot
affect an OS patch. An IAM change cannot affect a firewall remediation. Use
this matrix to avoid routing irrelevant events to the approval system:

```python
CHANGE_AFFECTS_REMEDIATION = {
    "IAM_POLICY":               {"IAM", "OS_PATCH", "MISCONFIGURATION"},
    "status_change":            {"OS_PATCH", "MISCONFIGURATION", "FIREWALL", "IAM"},
    "deletion":                 {"OS_PATCH", "MISCONFIGURATION", "FIREWALL", "IAM"},
    "firewall_rule_change":     {"FIREWALL", "MISCONFIGURATION"},
    "network_interface_change": {"FIREWALL", "MISCONFIGURATION"},
    "service_account_change":   {"IAM", "OS_PATCH"},
    "critical_label_change":    {"OS_PATCH", "MISCONFIGURATION", "FIREWALL", "IAM"},
}
```

**Stage 3 — Proximity scope.**

Beyond a defined hop depth, changes cannot plausibly affect a remediation:

```python
PROXIMITY_HOPS = 1          # direct neighbours only for most change types
IAM_PROXIMITY_HOPS = 2      # IAM changes propagate further via SA chains
```

### 4.3 Filter implementation location

Implement in `graph/events/filter.py`. The `classify_change(event)` function
returns either a classified change dict or `None` (discard). The processor
calls this first and short-circuits if `None` is returned.

---

## 5. Proximity index

### 5.1 Purpose

Even after filtering, checking every pending approval against every material
event is an O(approvals × events) operation that does not scale. The proximity
index inverts the relationship: it maps asset names to the approval IDs whose
blast radius includes that asset. Change event arrives → O(1) Firestore lookup
→ only the relevant approvals are checked.

### 5.2 Firestore collection

```
/proximity_index/{sanitised_asset_name}
  asset_name: string
  approval_ids: [string]     # ArrayUnion / ArrayRemove operations
```

Document ID is the asset name with `/` and `.` replaced by `_`, truncated to
500 characters.

### 5.3 Lifecycle

- **On approval creation:** call `index_approval(approval_id, target_asset, blast_radius_assets)` — writes an entry for every asset in the blast radius plus the target itself.
- **On approval resolution** (any terminal state — approved, rejected, executed, invalidated, blocked): call `deindex_approval(...)` to clean up.
- **Blast radius assets** must be stored on the approval record at creation time (`blast_radius_assets: [string]`) so deindex can remove all entries without re-querying the graph.

### 5.4 Implementation location

`graph/events/proximity_index.py` with four functions:
`index_approval`, `deindex_approval`, `get_affected_approvals`, and
a maintenance function `cleanup_stale_entries` (called daily to remove
entries where the approval no longer exists in Firestore).

---

## 6. Tiered invalidation response

### 6.1 Five response levels

When a material change arrives and the proximity index returns affected
approvals, the response is not always "invalidate." It is proportional to
how significant the change is and how close to execution the approval is.

| Response | Description | When |
|---|---|---|
| `IGNORE` | Change recorded in graph, approval unaffected | After filter determines no impact on this specific approval |
| `ANNOTATE` | Change noted silently on approval record, no notification | Distant execution, non-critical change type |
| `WARN` | Approver notified, execution proceeds unless they object | Execution > 1 hour away, change is notable but not blocking |
| `INVALIDATE` | Approval voided, re-analysis triggered automatically | Material change to pending or approved remediation, execution not imminent |
| `HARD_BLOCK` | Execution stopped immediately, human review required | Any of: deletion, change-freeze label added, IAM change within 60 min of execution, resource status changed within 60 min of execution |

### 6.2 Response determination matrix

```
deletion of target resource                        → always HARD_BLOCK
change-freeze label added                          → always HARD_BLOCK
IAM_POLICY change, execution ≤ 60 min away         → HARD_BLOCK
IAM_POLICY change, execution > 60 min away         → INVALIDATE
status_change, APPROVED, execution ≤ 60 min        → HARD_BLOCK
status_change, APPROVED, execution > 60 min        → INVALIDATE
status_change, PENDING                             → INVALIDATE
critical_label_change (non-freeze), PENDING        → INVALIDATE
critical_label_change (non-freeze), APPROVED       → WARN
service_account_change, PENDING                    → INVALIDATE
service_account_change, APPROVED, ≤ 60 min         → HARD_BLOCK
firewall_rule_change, PENDING                      → ANNOTATE (if unrelated to fix scope)
any change, execution > 24 hours away              → ANNOTATE
```

### 6.3 Re-analysis on INVALIDATE

When an approval is invalidated, the agent must automatically re-run the full
analysis pipeline (triage → impact → pre-flight → plan → new approval card).
The re-analysis is triggered by writing a task to Cloud Tasks with a 2-minute
delay (to allow any related events to settle). The new approval card should
note that it supersedes an invalidated approval and summarise what changed.

### 6.4 Approval record fields to add

**Add these fields** to the approval Firestore document schema (extends section
8 of main spec):

```
blast_radius_assets: [string]       # required for proximity index deindex
scheduled_execution_at: timestamp   # required for imminence checks
change_annotations: [{              # ANNOTATE responses
  change_type: string,
  asset: string,
  recorded_at: string,
  reason: string,
}]
warnings: [string]                  # WARN responses
invalidation_reason: string
invalidated_at: timestamp
block_reason: string
blocked_at: timestamp
reanalysis_task_id: string          # Cloud Tasks task ID for re-analysis
supersedes_approval_id: string      # if this is a re-analysis of a prior approval
```

---

## 7. Repository additions

The following files must be **added** to the repository structure in section 2
of the main spec:

```
graph/
  events/
    processor.py          # Cloud Run service: Pub/Sub push endpoints
    filter.py             # Change type significance filter pipeline
    handlers.py           # Per-content-type graph update handlers
    invalidation.py       # Tiered invalidation response logic
    proximity_index.py    # Asset → approval reverse index
infrastructure/
  setup_feeds.py          # One-time CAI feed creation at onboarding
  setup_log_sink.py       # One-time audit log sink creation at onboarding
agent/
  agents/
    preflight_agent.py    # Phase 1: deterministic pre-flight checks
  tools/
    regression_monitor.py # Post-fix error rate monitoring + auto-rollback
    rollback_tools.py     # Rollback artifact creation and execution
    confidence.py         # Confidence score computation
config/
  policies.py             # Pydantic models for autonomous execution policies
ui/
  src/
    pages/
      Policies.tsx        # Policy authoring UI
    components/
      PreflightChecklist.tsx   # Pre-flight results display in approval card
      ConfidenceScore.tsx      # Confidence score display component
      RollbackButton.tsx       # One-click rollback in approval card
```

---

## 8. Infrastructure additions

**Add to `terraform/main.tf`:**

```hcl
# Pub/Sub topics for event-driven graph updates
resource "google_pubsub_topic" "asset_change_events" {
  name = "asset-change-events"
}

resource "google_pubsub_topic" "audit_change_events" {
  name = "audit-change-events"
}

# Push subscriptions to the event processor Cloud Run service
resource "google_pubsub_subscription" "asset_events_push" {
  name  = "asset-events-push"
  topic = google_pubsub_topic.asset_change_events.name

  push_config {
    push_endpoint = "${google_cloud_run_service.event_processor.status[0].url}/events/asset"
    oidc_token {
      service_account_email = google_service_account.agent_sa.email
    }
  }

  ack_deadline_seconds       = 60
  message_retention_duration = "86400s"  # 24 hours
  retry_policy {
    minimum_backoff = "10s"
    maximum_backoff = "600s"
  }
}

resource "google_pubsub_subscription" "audit_events_push" {
  name  = "audit-events-push"
  topic = google_pubsub_topic.audit_change_events.name

  push_config {
    push_endpoint = "${google_cloud_run_service.event_processor.status[0].url}/events/audit"
    oidc_token {
      service_account_email = google_service_account.agent_sa.email
    }
  }

  ack_deadline_seconds       = 60
  message_retention_duration = "86400s"
  retry_policy {
    minimum_backoff = "10s"
    maximum_backoff = "600s"
  }
}

# Event processor Cloud Run service
resource "google_cloud_run_service" "event_processor" {
  name     = "scc-agent-event-processor"
  location = var.region

  template {
    spec {
      service_account_name = google_service_account.agent_sa.email
      containers {
        image = var.event_processor_image
        env {
          name  = "NEO4J_URI"
          value = "bolt://neo4j.neo4j.svc.cluster.local:7687"
        }
        env {
          name  = "GOOGLE_CLOUD_PROJECT"
          value = var.project_id
        }
        resources {
          limits = {
            cpu    = "1"
            memory = "512Mi"
          }
        }
      }
    }
    metadata {
      annotations = {
        "autoscaling.knative.dev/maxScale" = "10"
        "autoscaling.knative.dev/minScale" = "1"  # keep warm for latency
      }
    }
  }
}

# Firestore processed_events collection TTL policy (idempotency keys)
# TTL field: expires_at (set to 24h from message receipt)
# Configure via Firestore console or gcloud — TTL policies are not
# yet fully supported in Terraform as of spec date.
```

**Add to `terraform/iam.tf`:**

```hcl
# Additional roles needed for event-driven feeds
resource "google_organization_iam_member" "asset_feed_creator" {
  org_id = var.org_id
  role   = "roles/cloudasset.owner"  # required to create org-level feeds
  member = "serviceAccount:${google_service_account.agent_sa.email}"
}

resource "google_project_iam_member" "log_sink_creator" {
  project = var.project_id
  role    = "roles/logging.configWriter"
  member  = "serviceAccount:${google_service_account.agent_sa.email}"
}

resource "google_pubsub_topic_iam_member" "asset_events_publisher" {
  topic  = google_pubsub_topic.asset_change_events.name
  role   = "roles/pubsub.publisher"
  # CAI service account needs publish rights to deliver feed events
  member = "serviceAccount:service-${var.org_number}@gcp-sa-cloudasset.iam.gserviceaccount.com"
}
```

---

## 9. Revised open questions

The following entries **replace or extend** the open questions table in section
15 of the main spec.

| # | Question | Decision | Notes |
|---|---|---|---|
| 1 | Neo4j Community vs Spanner Graph | **Neo4j Community** — per-customer deployment, single org, graph fits comfortably in 4 vCPU / 16GB. Revisit only if org size exceeds ~500k resources or if operational overhead of GKE becomes a concern. Spanner Graph is a developer experience argument, not a scale argument at this deployment model. | Closed |
| 2 | Gemini model selection | gemini-2.0-pro for plan generation, gemini-2.0-flash for triage, dormancy, and pre-flight interpretation | Closed |
| 3 | Multi-tenant vs per-customer | Per-customer deployment in customer's own GCP project | Closed |
| 4 | IAM tightening execution | PR by default; direct API only if policy explicitly enables it and blast_level = LOW and confidence ≥ 0.85 | Closed |
| 5 | Owner label fallback | label `owner=` → project-level `owner=` → config default approver | Closed |
| 6 | Config UI auth | Identity-Aware Proxy, Google Workspace identity | Closed |
| 7 | Max findings per cycle | 100 per cycle, excess queued to next cycle | Closed |
| 8 | ITSM integration | Jira v1, ServiceNow v2 | Open |
| 9 | Rollback execution scope | Automated for OS patches (snapshot-based). Manual for IAM and firewall. PR revert for Terraform. | Closed |
| 10 | Dormancy threshold | 30 days default, configurable per customer | Closed |
| 11 | Autonomous execution default tier | Tier 3 (full human review) on initial activation. Customer graduates to Tier 2 and Tier 1 per finding category after reviewing outcome data. | Closed |
| 12 | Confidence score threshold for Tier 1 | Default 0.90. Customer-configurable per policy down to 0.80 minimum floor. | Closed |
| 13 | Event processor min instances | 1 (keep-warm) — latency matters for invalidation. Scale to max 10 on event bursts. | Closed |
| 14 | Proximity index cleanup | Daily maintenance job removes stale entries where approval_id no longer exists in Firestore | Closed |
| 15 | Regression monitor duration | 30 minutes post-fix, 60-second check interval, 2 standard deviation threshold | Open — tune based on first customer data |
| 16 | Policy simulation lookback window | 30 days of historical findings for policy authoring simulation | Open |
| 17 | CAI feed relationship types scope | Start with network interface, subnetwork, and SA attachment only — these are the highest-signal relationship changes. Expand based on observed invalidation patterns. | Open |

---

*End of addendum. Apply all sections to the main spec v1.1 before beginning development.*
*Addendum version: 1.0.0 — 2026-04-25*
