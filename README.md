# SCC Remediation Agent

An open-source autonomous security remediation agent for Google Cloud, built with [Google ADK](https://google.github.io/adk-docs/) and deployable via [agents-cli](https://github.com/google/agents-cli).

The agent connects to Security Command Center (SCC), builds a persistent asset graph of your GCP organisation, and autonomously remediates security findings — with human approval gates, blast radius analysis, and full audit trails. Available on [Agent Garden](#agent-garden) for one-click deployment via Gemini Enterprise Agent Platform.

---

## How it works

```
SCC findings ──► Triage ──► Blast radius analysis ──► Remediation plan
                                    │                        │
                               Asset graph               Auto-approve?
                               (Neo4j)                  ┌──Yes──► Execute fix
                                                         └──No───► Approval card
                                                                    (Chat / PD / Jira)
                                                                         │
                                                                    Approved?
                                                                    ├──Yes──► Execute ──► Verify ──► Mute finding
                                                                    ├──No───► Discard
                                                                    └──Defer─► Schedule to maintenance window
```

1. **Ingestion** — pulls findings from SCC, assets from Cloud Asset Inventory, IAM bindings from Policy Analyser, and network topology from Network Intelligence Center every 15 minutes (or real-time via Pub/Sub)
2. **Graph** — builds a Neo4j asset graph tracking resource relationships, environments, and security posture across your entire org
3. **Triage** — filters findings to your configured scope and severity threshold; ranks by attack exposure score
4. **Impact analysis** — traverses the graph to determine blast radius, prod dependencies, IAM lateral movement paths, and internet exposure
5. **Plan** — uses Gemini to generate a structured remediation plan with rollback steps
6. **Approval** — routes high-impact changes through a human approval workflow; low-risk dormant assets can be auto-approved
7. **Execute** — applies fixes via OS Config patch jobs, IAM API, or Terraform PRs via Cloud Build
8. **Verify** — re-queries SCC to confirm closure, updates the graph, and mutes the resolved finding

**Dry-run mode is on by default.** The agent generates plans but takes no action until you explicitly enable execution in the configuration UI.

---

## Architecture

```
┌─────────────────────────────────────────────────────────────┐
│                   Customer GCP Organisation                  │
│                                                             │
│  ┌──────────────┐    ┌────────────┐    ┌─────────────────┐  │
│  │     SCC      │    │   Cloud    │    │    Network      │  │
│  │  (findings)  │    │   Asset    │    │  Intelligence   │  │
│  └──────┬───────┘    │ Inventory  │    │    Center       │  │
│         │            └─────┬──────┘    └────────┬────────┘  │
│         └──────────────────┼───────────────────-┘           │
│                            ▼                                │
│                   ┌─────────────────┐                       │
│                   │  Ingestion jobs │  (Cloud Scheduler)    │
│                   └────────┬────────┘                       │
│                            ▼                                │
│                   ┌─────────────────┐                       │
│                   │   Neo4j Graph   │  (GKE, private)       │
│                   │  (asset graph)  │                       │
│                   └────────┬────────┘                       │
│                            ▼                                │
│  ┌────────────────────────────────────────────────────┐     │
│  │              SCC Remediation Agent                  │     │
│  │                  (Cloud Run)                        │     │
│  │                                                    │     │
│  │   Triage → Impact → Plan → Approve → Execute       │     │
│  │                                                    │     │
│  └────────┬──────────────────────────┬───────────────┘     │
│           │                          │                      │
│           ▼                          ▼                      │
│  ┌─────────────────┐       ┌──────────────────┐            │
│  │    Firestore    │       │   Approval card  │            │
│  │  (config, audit)│       │  (Chat/PD/Jira)  │            │
│  └─────────────────┘       └──────────────────┘            │
│                                                             │
│  ┌──────────────────────────────────────────────────────┐   │
│  │              Config UI  (Cloud Run + IAP)            │   │
│  └──────────────────────────────────────────────────────┘   │
└─────────────────────────────────────────────────────────────┘
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
# Edit terraform.tfvars with your project_id, org_id, region, neo4j_password
```

### 2. Provision infrastructure

```bash
cd terraform
terraform init
terraform apply
cd ..
```

This creates:
- GKE cluster with Neo4j (private, cluster-internal only)
- Firestore database
- Service account with least-privilege org-level roles
- Secret Manager secret for the Neo4j password
- All required GCP APIs enabled

### 3. Deploy the agent

```bash
uvx google-agents-cli setup   # first time only
agents-cli deploy
```

The agent is deployed to Cloud Run with the service account provisioned by Terraform.

### 4. Configure the agent

Open the Config UI (Cloud Run URL printed by `agents-cli deploy`) and complete the 5-step wizard:

1. **Scope** — select which projects or label-filtered assets to monitor
2. **Severity** — set the minimum severity threshold (Critical/High/Medium/All)
3. **Approval policy** — configure approvers, tiers, and maintenance windows
4. **Execution** — choose remediation modes (OS patch, misconfiguration, IAM); keep dry-run on initially
5. **Notifications** — connect Google Chat, PagerDuty, and/or Jira

### 5. Review the shadow mode report

The agent runs for 24 hours in dry-run and sends a report showing exactly what it would have done — which findings it would have remediated, who would have received approval requests, and what the blast radius analysis found.

When you're satisfied, enable execution in the Config UI.

---

## Configuration reference

The agent is configured per-customer via a `CustomerConfig` document in Firestore (`/configs/{customer_id}`). The Config UI writes this for you, but you can also write it directly.

```python
CustomerConfig(
    customer_id="acme-prod",
    org_id="123456789",
    display_name="ACME Production",
    dry_run=True,                                    # safe default
    scope=ScopeConfig(
        project_ids=["my-project-id"],               # or leave empty for all projects
        include_labels=[LabelFilter(key="env", value="prod")],
        exclude_labels=[LabelFilter(key="skip-remediation", value="true")],
    ),
    severity_threshold=SeverityThreshold.HIGH_PLUS,  # CRITICAL + HIGH
    approval_policy=ApprovalPolicy(
        auto_approve_enabled=True,
        tiers=[
            ApprovalTier(
                name="auto",
                condition={"severity": ["LOW", "MEDIUM"], "env": ["dev"]},
                requires_approval=False,
                auto_approve_eligible=True,
            ),
            ApprovalTier(
                name="manual",
                condition={"severity": ["HIGH", "CRITICAL"]},
                requires_approval=True,
                auto_approve_eligible=False,
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
            )
        ],
        default_maintenance_window=MaintenanceWindow(
            days_of_week=[1, 2, 3, 4],   # Tue–Fri
            start_time_utc="02:00",
            end_time_utc="05:00",
            timezone="America/New_York",
        ),
        notification_channels=["google_chat"],
    ),
    execution=ExecutionConfig(
        enabled_modes=[RemediationMode.OS_PATCH, RemediationMode.MISCONFIGURATION],
    ),
    notifications=NotificationConfig(
        google_chat_space="spaces/XXXXXXXX",
    ),
)
```

**Auto-approve eligibility** — a finding is auto-approved only when all of the following are true:
- `auto_approve_enabled` is `True`
- Blast radius is LOW (zero prod downstream dependencies)
- Asset dormancy class is `DORMANT` or `PERIODIC`
- No change freeze is active (resource or project label `change-freeze=true`)
- `dry_run` is `False`

---

## Asset labelling

The agent uses GCP resource labels to determine environment, team, and scope. Apply these labels to your resources for best results:

| Label key | Example values | Purpose |
|---|---|---|
| `env` | `prod`, `staging`, `dev` | Environment classification (drives approval tier) |
| `team` | `platform`, `backend` | Team ownership (used in approval routing) |
| `owner` | `alice@acme.com` | Resource owner (escalation target) |
| `data-class` | `pii`, `internal`, `public` | Data sensitivity (elevates blast radius score) |
| `maint-window` | `tue-0200-utc` | Resource-specific maintenance window override |
| `change-freeze` | `true` | Prevent any remediation on this resource |
| `skip-remediation` | `true` | Exclude from agent scope entirely |

---

## Approval workflow

When a finding requires human approval, the agent creates an approval record in Firestore and sends a card to configured channels:

**Google Chat card:**
- Finding severity and category
- Affected asset and team
- Blast radius summary (downstream dependencies, prod impact)
- Risk assessment from Gemini
- Estimated downtime and reboot requirement
- Rollback plan
- **Approve / Reject / Defer to window** buttons

Approvals expire after a configurable grace period. Unanswered approvals are escalated to fallback approvers.

---

## Ingestion schedule

| Job | Schedule | Source |
|---|---|---|
| Asset full sync | Every 6 hours | Cloud Asset Inventory |
| Finding delta sync | Every 15 minutes | Security Command Center |
| IAM sync | Every 1 hour | Policy Analyser |
| Network sync | Every 6 hours | Network Intelligence Center |

Critical findings also trigger real-time processing via SCC Pub/Sub notifications.

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

### Project structure

```
scc-remediation-agent/
├── agent.yaml              # agents-cli entrypoint + Agent Garden marketplace config
├── app/
│   ├── agent.py            # Root agent (ADK)
│   └── tools/
│       ├── scc_tools.py    # SCC API wrappers
│       ├── graph_tools.py  # Neo4j query wrappers
│       ├── network_tools.py
│       ├── osconfig_tools.py
│       └── approval_tools.py
├── config/
│   ├── schema.py           # Pydantic CustomerConfig models
│   └── validator.py        # Config validation + dry-run preview
├── graph/
│   ├── ingestion/          # Asset, finding, IAM, and relationship ingesters
│   ├── schema/             # Neo4j Cypher constraints and node/relationship definitions
│   └── queries/            # Blast radius, IAM paths, dormancy Cypher queries
├── scheduler/
│   ├── windows.py          # Maintenance window computation
│   └── freeze.py           # Change freeze detection
├── terraform/              # GCP infrastructure (GKE, Firestore, IAM, Secret Manager)
├── ui/                     # Config wizard + dashboard (React)
└── tests/
    └── eval/               # ADK eval sets and config
```

---

## Security model

- The agent service account follows **least privilege** — no `roles/owner`, `roles/editor`, or `roles/iam.admin`
- All secrets (Neo4j password, notification keys) are stored in **Secret Manager**, never in environment variables or source code
- Neo4j is accessible only from within the GKE cluster via internal DNS — no external load balancer
- The Config UI is protected by **Identity-Aware Proxy** — no unauthenticated access
- Terraform changes go through **Cloud Build** with a separate limited-privilege service account
- Config history in Firestore is **append-only** — no version is ever deleted
- All inter-service communication uses **Workload Identity** — no long-lived service account keys

---

## Agent Garden

This agent is available on [Agent Garden](https://console.cloud.google.com/agent-garden) for customers on Gemini Enterprise Agent Platform. Install it with one click and Agent Platform provisions the required service account and roles automatically.

For deployment outside Agent Garden, use the [Quickstart](#quickstart) above.

---

## Contributing

Contributions welcome. Please open an issue before starting significant work.

Areas where help is most valuable:
- Additional remediation modes (Firewall rule tightening, GCS bucket policy fixes)
- PagerDuty and Jira approval channel implementations (`app/tools/approval_tools.py`)
- Network Intelligence Center integration (`app/tools/network_tools.py`)
- Unit test coverage (`tests/unit/`)
- Additional eval cases (`tests/eval/evalsets/`)

---

## License

Apache 2.0 — see [LICENSE](LICENSE).
