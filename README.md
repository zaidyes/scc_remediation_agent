# SCC Remediation Agent

An open-source autonomous security remediation agent for Google Cloud, built with [Google ADK](https://google.github.io/adk-docs/) and deployable via [agents-cli](https://github.com/google/agents-cli).

The agent connects to Security Command Center (SCC), builds a persistent asset graph of your GCP organisation, and remediates security findings with configurable autonomy — from fully automated execution to human-in-the-loop approval gates. Available on [Agent Garden](#agent-garden) for one-click deployment.

---

## How it works

```
SCC findings ──► Triage ──► Impact analysis ──► Pre-flight checks ──► Remediation plan
                                  │                                          │
                             Asset graph                              Confidence score
                             (Neo4j)                                        │
                                                          ┌─────────────────┼──────────────────┐
                                                          │                 │                  │
                                                     Tier 1             Tier 2             Tier 3
                                                  (autonomous)     (single-tap)        (expert review)
                                                       │                 │                  │
                                                   Execute           Approval          Approval card
                                                       │             card (UI)        (Chat/PD/Jira)
                                                       │                 │                  │
                                                  Verify ◄──────────────┴──────────────────-┘
                                                       │
                                              Regression monitor (30 min)
                                                       │
                                              Mute resolved finding
```

### Pipeline stages

1. **Ingestion** — pulls findings from SCC, assets from Cloud Asset Inventory (CAI), IAM bindings from Policy Analyser, and network topology from Network Intelligence Center. CAI feeds deliver real-time change events via Pub/Sub.
2. **Graph** — builds a Neo4j asset graph tracking resource relationships, environments, and security posture across the entire org. Kept live by an event processor that handles CAI feed and Cloud Audit Log events.
3. **Triage** — filters findings to your configured scope and severity threshold; ranks by attack exposure score.
4. **Impact analysis** — traverses the graph to determine blast radius, prod downstream dependencies, IAM lateral movement paths, and internet exposure.
5. **Pre-flight checks** — deterministic GCP API calls that confirm the asset is safe to touch (change freeze, active connections, snapshot policy, last IAM role use, etc.). Each check returns PASS / WARN / BLOCK.
6. **Confidence scoring** — combines pre-flight results, blast level, asset dormancy, and 30-day historical success rate into a 0–100% confidence score.
7. **Execution tier** — the confidence score and your execution policies determine the tier:
   - **Tier 1** — fully autonomous; executes immediately with no human involved
   - **Tier 2** — sends a single-tap confirmation card; 4-hour timeout before escalating to Tier 3
   - **Tier 3** — full expert review via Google Chat, PagerDuty, and/or Jira
8. **Execute** — applies fixes via OS Config patch jobs, IAM API, Compute API, or Terraform PRs via Cloud Build. Rollback artifacts are captured pre-execution.
9. **Verify** — type-specific checks confirm the finding is closed (OS Config vuln report, NIC Connectivity Test, `analyzeIamPolicy`). Falls back to SCC state polling for misconfiguration findings.
10. **Regression monitor** — runs for 30 minutes post-execution watching Cloud Monitoring error rates against a 7-day baseline. Triggers automatic rollback if a 2σ deviation is detected.

**Dry-run mode is on by default.** The agent generates plans but takes no action until you explicitly enable execution in the Config UI or Policies page.

---

## Architecture

```
┌──────────────────────────────────────────────────────────────────┐
│                     Customer GCP Organisation                     │
│                                                                  │
│  ┌──────────┐  ┌───────────────┐  ┌────────────────────────────┐ │
│  │   SCC    │  │ Cloud Asset   │  │   Cloud Audit Logs         │ │
│  │(findings)│  │  Inventory    │  │   (Admin Activity)         │ │
│  └────┬─────┘  └──────┬────────┘  └────────────┬───────────────┘ │
│       │               │  CAI feeds              │ Log sink        │
│       │               ▼                         ▼                 │
│       │    ┌─────────────────────────────────────────────────┐    │
│       │    │         Pub/Sub topics                          │    │
│       │    │   asset-change-events   audit-change-events     │    │
│       │    └──────────────────┬──────────────────────────────┘    │
│       │                       │ push subscriptions                │
│       │                       ▼                                   │
│       │         ┌──────────────────────────┐                      │
│       │         │   Event Processor        │  (Cloud Run,         │
│       │         │   (graph/events/)        │   internal-only)     │
│       │         │  filter → Neo4j update   │                      │
│       │         │  → invalidate approvals  │                      │
│       │         └──────────────────────────┘                      │
│       │                                                           │
│       ▼                                                           │
│  ┌─────────────────────────────────────────────────────────────┐  │
│  │               SCC Remediation Agent  (Cloud Run)            │  │
│  │                                                             │  │
│  │  Triage → Impact → Pre-flight → Confidence → Tier → Plan   │  │
│  │                         │                                  │  │
│  │                    Execute → Verify → Regression monitor   │  │
│  └──────────┬──────────────────────────────┬──────────────────┘  │
│             │                              │                      │
│             ▼                              ▼                      │
│  ┌─────────────────────┐       ┌───────────────────────────┐     │
│  │      Firestore      │       │    Approval channels      │     │
│  │  configs, approvals │       │  Google Chat / PagerDuty  │     │
│  │  audit, graph index │       │  Jira / Config UI         │     │
│  └─────────────────────┘       └───────────────────────────┘     │
│                                                                   │
│  ┌────────────────────────────────────────────────────────────┐   │
│  │          Config UI + Dashboard  (Cloud Run + IAP)          │   │
│  └────────────────────────────────────────────────────────────┘   │
│                                                                   │
│  ┌──────────────────┐  (Compute Engine, no public IP, IAP SSH)    │
│  │  Neo4j  :7687    │                                             │
│  └──────────────────┘                                             │
└──────────────────────────────────────────────────────────────────┘
```

No customer data leaves your GCP organisation.

---

## Prerequisites

- A GCP organisation (not just a project)
- `gcloud` CLI authenticated with org-level permissions
- Terraform >= 1.5
- `uv` — `curl -LsSf https://astral.sh/uv/install.sh | sh`
- agents-cli — `uvx google-agents-cli setup`

---

## Quickstart

### 1. Clone and configure

```bash
git clone https://github.com/your-org/scc-remediation-agent
cd scc-remediation-agent

cp terraform/terraform.tfvars.example terraform/terraform.tfvars
# Edit terraform.tfvars — required: project_id, org_id, neo4j_password
```

### 2. Provision infrastructure

```bash
cd terraform
terraform init
terraform apply
cd ..
```

This provisions:
- Neo4j on a Compute Engine VM (no public IP; IAP SSH only)
- Pub/Sub topics (`asset-change-events`, `audit-change-events`) with push subscriptions
- Event processor Cloud Run service (internal ingress only)
- Cloud Tasks queues (`approval-escalations`, `remediation-execution`, `scc-remediation-tasks`)
- Firestore database for agent state
- Service account with least-privilege org-level roles
- Secret Manager secret for the Neo4j password

### 3. Set up CAI feeds and log sink

```bash
# Org-level Cloud Asset Inventory feeds → Pub/Sub
python infrastructure/setup_feeds.py --project-id YOUR_PROJECT_ID --org-id YOUR_ORG_ID

# Org-level Cloud Audit Log sink → audit-change-events topic
python infrastructure/setup_log_sink.py --project-id YOUR_PROJECT_ID --org-id YOUR_ORG_ID
```

### 4. Deploy the agent

```bash
uvx google-agents-cli setup   # first time only
agents-cli deploy
```

### 5. Configure the agent

Open the Config UI (URL printed by `agents-cli deploy`) and complete the setup wizard:

1. **Scope** — select projects or label-filtered assets to monitor
2. **Severity** — set the minimum severity threshold
3. **Approval policy** — configure approvers, tiers, and maintenance windows
4. **Execution** — choose remediation modes; keep dry-run on initially
5. **Notifications** — connect Google Chat, PagerDuty, and/or Jira

### 6. Configure execution policies

Go to the **Policies** tab and create at least one policy before enabling execution:

- **Tier 1** — autonomous execution for low-risk, high-confidence findings
- **Tier 2** — single-tap approval for medium-risk findings

Each policy specifies remediation type, severity levels, minimum confidence threshold, and maximum blast radius. A 30-day simulation shows how many past findings would have been actioned at each tier.

### 7. Review the shadow mode report

Run in dry-run for 24 hours. The agent logs exactly what it would have done — which findings, which approvers, and the confidence breakdown.

When satisfied, disable dry-run in the Config UI.

---

## Three-tier execution

| Tier | Name | Trigger | Approval |
|------|------|---------|---------|
| 1 | Autonomous | Active Tier 1 policy + confidence ≥ threshold + blast = LOW | None — executes immediately |
| 2 | Policy-assisted | Active Tier 2 policy + confidence ≥ 0.70 + blast ≤ MEDIUM | Single tap in Config UI; escalates to Tier 3 after 4 hours |
| 3 | Expert review | Default for all other findings | Full approval card (Chat/PD/Jira); configurable grace period |

### Confidence score

Combines four signals into a 0–100% score:

| Signal | Effect |
|--------|--------|
| Pre-flight BLOCK | Clamps score to 0% (plan is blocked) |
| Pre-flight WARN | −15% per warning |
| Blast radius | LOW: 0%, MEDIUM: −15%, HIGH: −40%, CRITICAL: −70% |
| Asset dormancy | DORMANT/PERIODIC: +10% |
| Historical outcomes | 30% weight of past 30-day success rate for this finding class and remediation type |

---

## Pre-flight checks

Run before every remediation plan. Each check is a direct GCP API call — no LLM involved.

**OS patch findings:**

| Check | BLOCK if | WARN if |
|-------|----------|---------|
| Change freeze label | `change-freeze=true` on resource or project | — |
| MIG membership | Instance is in a managed group | — |
| Active SSH sessions | — | Session active in last 5 min |
| Recent deployment | — | Deployed in last 30 min |
| Snapshot policy | — | No snapshot policy configured |
| Load balancer health | — | Instance is a serving backend |
| Reboot required | — | Patch requires reboot |

**Firewall findings:**

| Check | BLOCK if | WARN if |
|-------|----------|---------|
| Change freeze | `change-freeze=true` | — |
| Active traffic | Traffic on target port in last 5 min (VPC flow logs) | — |
| Cloud Armor overlap | — | Target range covered by Cloud Armor rule |
| SA auth from blocked range | — | SA used from a range in scope |

**IAM findings:**

| Check | BLOCK if | WARN if |
|-------|----------|---------|
| Change freeze | `change-freeze=true` | — |
| Role last used | — | Role used in last 7 days |
| Redundant grants | — | Same permission granted by other binding |
| Active SA keys | — | SA has active user-managed keys |

---

## Rollback

Every Tier 1 and Tier 2 execution captures a rollback artifact before making changes:

| Remediation type | Artifact |
|-----------------|---------|
| OS patch | Compute disk snapshot + restore command |
| Firewall | Firewall rule JSON export to GCS |
| IAM | `gcloud projects add-iam-policy-binding` command |
| GitOps PR | PR revert reference |

Rollback is available for **24 hours** after execution. Trigger it from the Dashboard or call `POST /api/rollback/{approval_id}`.

---

## Event-driven graph freshness

The asset graph stays current without polling. When a resource changes in your org:

1. Cloud Asset Inventory delivers the change to the `asset-change-events` Pub/Sub topic via a CAI feed.
2. Cloud Audit Logs forward admin activity to `audit-change-events` via a log sink.
3. The **event processor** (`graph/events/processor.py`) receives the Pub/Sub push, runs a three-stage filter (change type significance → remediation relevance → proximity hops), and updates the Neo4j graph.
4. It then checks the **proximity index** — a Firestore inverted index mapping each asset to any pending approval whose blast radius includes it.
5. For each affected approval, the event processor applies a **tiered invalidation response**:

| Level | Condition | Action |
|-------|-----------|--------|
| IGNORE | Change is irrelevant | Nothing |
| ANNOTATE | Change is distant (>24h to execution) | Record annotation on approval |
| WARN | Label change on approved approval | Notify approver; execution continues unless objected |
| INVALIDATE | IAM change, status change, SA change | Void approval; re-analyse in 2 minutes |
| HARD_BLOCK | Deletion, freeze label, IAM/SA change ≤60min to execution | Stop execution; require human resolution |

---

## Approval workflow

Approval cards include:

- Finding severity, category, and execution tier
- Asset name and blast radius (level + prod downstream count)
- Confidence score and pre-flight check summary (PASS/WARN/BLOCK)
- Risk assessment and estimated downtime
- Rollback plan (first 3 steps)
- **Approve / Reject / Defer to maintenance window** buttons
- Expiry timestamp and approval ID

Unanswered approvals escalate to fallback approvers after a configurable timeout.

---

## Asset labelling

Apply these GCP resource labels for best results:

| Label key | Example values | Purpose |
|-----------|---------------|---------|
| `env` | `prod`, `staging`, `dev` | Environment classification (drives approval tier) |
| `team` | `platform`, `backend` | Team ownership (approval routing) |
| `owner` | `alice@acme.com` | Resource owner (escalation target) |
| `data-class` | `pii`, `internal`, `public` | Data sensitivity (elevates blast radius score) |
| `maint-window` | `tue-0200-utc` | Resource-specific maintenance window override |
| `change-freeze` | `true` | Prevent any remediation (triggers HARD_BLOCK) |
| `skip-remediation` | `true` | Exclude from agent scope entirely |

---

## Demo environment

For testing against a real org without touching production resources:

```bash
bash scripts/demo.sh
```

The script:
1. Prompts for org ID and billing account
2. Runs Terraform to create a demo folder with three isolated projects (`infra`, `web`, `data`)
3. Seeds intentional misconfigurations (public bucket, open SSH/RDP, owner-bound SA)
4. Spins up a Neo4j VM (no public IP; IAP tunnel opened automatically)
5. Writes a `.env` file and seeds a dry-run Firestore config
6. Launches the agent pipeline and UI

Tear down with `terraform -chdir=terraform/demo destroy`.

---

## Configuration reference

The agent is configured per-customer via Firestore (`/configs/{customer_id}`). The Config UI writes this automatically.

### Execution policies

Execution policies are the primary control surface for autonomous remediation. They live under `policies: []` on the customer config and are managed in the **Policies** tab of the Config UI.

```python
ExecutionPolicy(
    policy_id="tier1-low-risk",
    customer_id="acme-prod",
    remediation_type="OS_PATCH",          # or FIREWALL, IAM, MISCONFIGURATION, ANY
    severity_levels=["CRITICAL", "HIGH"],
    finding_categories=[],                # empty = all categories
    asset_label_conditions={"env": "dev"},# only match dev assets
    min_confidence_threshold=0.90,        # 90% required for Tier 1
    max_blast_radius="LOW",               # exclude anything above LOW blast
    tier=1,                               # 1=autonomous, 2=single-tap
    active=True,
)
```

The Policies page runs a **30-day simulation** against historical findings, showing how many would have been actioned at each tier, and flagging edge cases (e.g. findings with no confidence score, or below-threshold confidence).

### Full CustomerConfig example

```python
CustomerConfig(
    customer_id="acme-prod",
    org_id="123456789",
    display_name="ACME Production",
    dry_run=True,
    scope=ScopeConfig(
        project_ids=["my-project-id"],
        include_labels=[LabelFilter(key="env", value="prod")],
        exclude_labels=[LabelFilter(key="skip-remediation", value="true")],
    ),
    severity_threshold="HIGH_PLUS",
    approval_policy=ApprovalPolicy(
        auto_approve_enabled=True,
        tiers=[
            ApprovalTier(
                name="fast-track",
                condition={"severity": ["CRITICAL", "HIGH"]},
                requires_approval=True,
                grace_period_minutes=30,
                escalate_after_minutes=15,
            ),
        ],
        approvers=[
            Approver(
                name="Security team",
                type="group",
                address="security-team@acme.com",
                severity_levels=["CRITICAL", "HIGH"],
                channel="google_chat",
                fallback_address="security-oncall@acme.com",
            )
        ],
        default_maintenance_window=MaintenanceWindow(
            days_of_week=[1, 2, 3, 4],
            start_time_utc="02:00",
            end_time_utc="05:00",
            timezone="America/New_York",
        ),
        notification_channels=["google_chat"],
    ),
    execution=ExecutionConfig(
        enabled_modes=["OS_PATCH", "MISCONFIGURATION"],
    ),
    notifications=NotificationConfig(
        google_chat_space="spaces/XXXXXXXX",
    ),
    policies=[
        {
            "policy_id": "tier1-dev-patch",
            "remediation_type": "OS_PATCH",
            "severity_levels": ["HIGH"],
            "asset_label_conditions": {"env": "dev"},
            "min_confidence_threshold": 0.90,
            "max_blast_radius": "LOW",
            "tier": 1,
            "active": True,
        }
    ],
)
```

---

## Agent harness architecture

The agent pipeline follows the five-layer harness pattern from the Claude Code architecture (arXiv 2604.14228). Three of the five layers are active in this codebase.

### Layer 1 — Context budget truncation (`app/tools/context_budget.py`)

Large GCP resource payloads (GKE clusters, VPCs) can exceed 200 KB of raw JSON. Every section injected into an LLM prompt is serialised through a three-stage budget reducer before the API call:

| Stage | Strategy | Trigger |
|-------|----------|---------|
| 1 | Full pretty-print (indent=2) | Fits within budget → return immediately |
| 2 | Field pruning + compact JSON | Remove `selfLink`, `etag`, `fingerprint`, `kind`, `id`; strip GCE metadata startup scripts; cap lists to 5 items |
| 3 | Hard character truncation | Last resort; appends `[CONTEXT_BUDGET: '...' truncated — N chars removed]` so the model knows data was cut |

Per-section budgets are tunable via env vars:

| Section | Default | Env var |
|---------|---------|---------|
| `resource_data` (CAI blob) | 32,000 chars | `CONTEXT_BUDGET_RESOURCE_DATA` |
| `impact` (blast radius output) | 16,000 chars | `CONTEXT_BUDGET_IMPACT` |
| `preflight` (pre-flight results) | 8,000 chars | `CONTEXT_BUDGET_PREFLIGHT` |
| `finding` (SCC finding JSON) | 4,000 chars | `CONTEXT_BUDGET_FINDING` |

### Layer 2 — Dynamic tool pool assembly (`app/agent.py`)

Each impact sub-agent receives only the tools relevant to its remediation type, reducing schema tokens per model call and eliminating wrong-tool hallucinations.

| Type | Tools included | Tools excluded |
|------|---------------|----------------|
| `OS_PATCH` | blast_radius, dependency_chain, dormancy | iam_paths, network_exposure |
| `IAM` | blast_radius, iam_paths, dormancy | network_exposure, dependency_chain |
| `FIREWALL` | blast_radius, dependency_chain, network_exposure | iam_paths, dormancy |
| `MISCONFIGURATION` | All tools | — |

Tools can also be blocked globally at runtime via `AGENT_TOOL_DENY_LIST` (comma-separated function names), applied before any agent is constructed.

### Layer 3 — Subagent output compaction (`app/tools/agent_output.py`)

Each sub-agent passes only the fields its downstream consumer actually reads. Compaction is applied at agent boundaries before any data crosses to the next stage.

| Compaction function | Consumer | Fields kept | Typical reduction |
|---------------------|----------|-------------|-------------------|
| `compact_impact_for_plan()` | `PlanAgent.generate()` | blast_level, blast_radius_assets, network_exposure_summary, iam_paths[:5], downstream[:10] as name+env+team | ~65% |
| `compact_impact_for_approval()` | `dispatch_approval_request()` | blast_level, blast_radius_assets, prod/pii counts, internet_exposed | ~80% |
| `compact_impact_for_scoring()` | `compute_confidence_score()` | blast_level, dormancy_class only | ~95% |
| `compact_plan_for_verify()` | `VerifyAgent.verify()` | plan_id, finding_id, asset_name, remediation_type, cve_ids, connectivity_test_cases, iam_member, iam_role, blast_radius_assets | ~85% |

### Layer 4 — Per-action permission gate (`app/hooks.py`)

The `_builtin_per_step_safety_recheck` hook fires on every `PRE_STEP` event and re-checks both change-freeze status and Firestore approval liveness before executing each step. If either check fails, the hook sets `stop=True` and the execution loop halts immediately — closing the plan-vs-action safety gap that exists when approval state is only checked at plan time.

### Layer 5 — 24-event hook pipeline (`app/hooks.py`)

All 24 lifecycle events are wired in `app/main.py`. Custom hooks attach via `@hooks.on(event)` or `hooks.register(event, fn)`. Three built-in hooks are registered at import:

- `_builtin_per_step_safety_recheck` — PRE_STEP: change-freeze + approval liveness check
- `_builtin_audit_writer` — 10 events: structured Firestore audit writes
- `_builtin_transcript_logger` — POST_IMPACT/POST_PLAN/POST_VERIFY: opt-in agent reasoning transcripts (`AGENT_LOG_REASONING=true`)

---

## Ingestion schedule

| Job | Schedule | Source |
|-----|---------|--------|
| Asset full sync | Every 6 hours | Cloud Asset Inventory |
| Finding delta sync | Every 15 minutes | Security Command Center |
| IAM sync | Every 1 hour | Policy Analyser |
| Network sync | Every 6 hours | Network Intelligence Center |

Real-time changes arrive via CAI feeds and Cloud Audit Log sink (Pub/Sub push → event processor).

---

## Project structure

```
scc-remediation-agent/
├── app/
│   ├── __init__.py             # Vertex AI bootstrap; re-exports root_agent
│   ├── agent.py                # Root ADK agent (triage → impact → plan → verify sub-agents)
│   ├── main.py                 # Entry point; tier routing; _execute_plan; _dispatch_for_approval
│   ├── prompts.py              # All agent instruction strings
│   ├── agents/
│   │   ├── impact_agent.py     # Blast radius and dormancy analysis
│   │   ├── plan_agent.py       # Two-phase: pre-flight then Gemini plan generation
│   │   ├── preflight_agent.py  # Deterministic GCP API pre-flight checks
│   │   └── verify_agent.py     # Type-specific post-execution verification
│   └── tools/
│       ├── agent_output.py     # Subagent output compaction functions (Layer 3)
│       ├── approval_tools.py   # Firestore approval records; Chat/PD/Jira cards
│       ├── confidence.py       # Confidence score computation
│       ├── context_budget.py   # Three-stage LLM prompt budget enforcement (Layer 1)
│       ├── graph_tools.py      # Neo4j query wrappers
│       ├── hooks.py            # 24-event hook pipeline (Layer 5)
│       ├── network_tools.py    # Network Intelligence Center wrappers
│       ├── osconfig_tools.py   # OS Config patch job tools
│       ├── regression_monitor.py  # Cloud Monitoring baseline + auto-rollback
│       ├── rollback_tools.py   # Rollback artifact capture and execution
│       └── scc_tools.py        # SCC API wrappers
├── config/
│   ├── policies.py             # ExecutionPolicy Pydantic model + matches() logic
│   ├── schema.py               # CustomerConfig and all nested Pydantic models
│   └── validator.py            # Config validation + dry-run preview
├── graph/
│   ├── events/
│   │   ├── filter.py           # Three-stage change classification pipeline
│   │   ├── handlers.py         # Neo4j graph update handlers (IAM/resource/relationship)
│   │   ├── invalidation.py     # Five-level tiered invalidation (IGNORE→HARD_BLOCK)
│   │   ├── processor.py        # Cloud Run service: Pub/Sub push endpoints
│   │   └── proximity_index.py  # Firestore inverted index: asset → approval IDs
│   ├── ingestion/              # Asset, finding, IAM, and relationship ingesters
│   ├── schema/                 # Neo4j Cypher constraints and node definitions
│   └── queries/                # Blast radius, IAM paths, dormancy Cypher queries
├── infrastructure/
│   ├── setup_feeds.py          # Creates org-level CAI feeds → Pub/Sub
│   └── setup_log_sink.py       # Creates org-level Cloud Audit Log sink
├── scheduler/
│   ├── main.py                 # Webhook handler: Chat/PD/Jira + Cloud Tasks worker
│   ├── windows.py              # Maintenance window computation
│   └── freeze.py               # Change freeze detection
├── terraform/
│   ├── main.tf                 # Core infra: APIs, Pub/Sub, Cloud Tasks, event processor, Neo4j
│   ├── iam.tf                  # Service accounts and IAM bindings
│   ├── neo4j.tf                # Neo4j Compute Engine VM (no public IP, IAP)
│   ├── variables.tf
│   └── demo/                   # Isolated demo environment (folder + 3 projects + misconfigs)
├── ui/
│   ├── api/main.py             # Config API: config, findings, approvals, policies, rollback
│   └── src/
│       ├── App.tsx             # Nav shell (Dashboard / Policies / Config / Audit Log)
│       ├── components/
│       │   ├── ConfidenceScore.tsx     # Score bar + tier badge
│       │   ├── PreflightChecklist.tsx  # Collapsible PASS/WARN/BLOCK table
│       │   ├── RollbackButton.tsx      # Two-step confirm; 24 h window
│       │   └── ...wizard step components
│       └── pages/
│           ├── Dashboard.tsx   # Active findings + approval cards
│           ├── Policies.tsx    # Policy CRUD + 30-day simulation
│           ├── ConfigWizard.tsx
│           └── AuditLog.tsx
├── scripts/
│   └── demo.sh                 # End-to-end demo provisioning script
├── infrastructure/
│   ├── setup_feeds.py
│   └── setup_log_sink.py
└── tests/
    └── eval/                   # ADK eval sets and config
```

---

## Security model

- The agent service account follows **least privilege** — no `roles/owner`, `roles/editor`, or `roles/iam.admin`
- All secrets (Neo4j password, notification keys) are stored in **Secret Manager**, never in environment variables or source code
- Neo4j runs on a Compute Engine VM with **no public IP** — accessible only via IAP SSH tunnel or internal VPC
- The event processor Cloud Run service uses **internal-only ingress** — not reachable from the internet
- The Config UI is protected by **Identity-Aware Proxy** — no unauthenticated access
- Terraform changes go through **Cloud Build** with a separate limited-privilege service account
- Config history in Firestore is **append-only** — no version is ever deleted
- All inter-service calls use **OIDC tokens** — no long-lived service account keys
- Pub/Sub push subscriptions authenticate with a dedicated invoker service account

---

## Development

```bash
# Install dependencies
uv sync

# Run locally (dry-run, no GCP connection needed for most tests)
CUSTOMER_ID=test NEO4J_URI=bolt://localhost:7687 agents-cli run

# Run evals
agents-cli eval run --eval_set_file tests/eval/evalsets/basic.evalset.json \
                    --eval_config_file tests/eval/eval_config.json

# Run unit tests
uv run pytest tests/unit/
```

---

## Agent Garden

This agent is available on [Agent Garden](https://console.cloud.google.com/agent-garden) for customers on Gemini Enterprise Agent Platform. Install it with one click and Agent Platform provisions the required service account and roles automatically.

For deployment outside Agent Garden, use the [Quickstart](#quickstart) above.

---

## Contributing

Contributions welcome. Please open an issue before starting significant work.

Areas where help is most valuable:
- Additional remediation modules (GCS bucket policy fixes, VPC firewall tightening)
- Eval cases for new finding categories (`tests/eval/evalsets/`)
- Unit test coverage (`tests/unit/`)
- Additional pre-flight checks in `app/agents/preflight_agent.py`

---

## License

Apache 2.0 — see [LICENSE](LICENSE).
