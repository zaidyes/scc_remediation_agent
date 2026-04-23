# SCC Remediation Agent — Full Technical Specification

> **Document purpose:** This specification is intended to be read by Claude Code or another coding agent and built from end-to-end. It covers architecture, data models, agent logic, APIs, configuration schema, UI, and deployment. Follow the sections in order; each section's outputs are inputs to the next.

---

## Table of contents

1. [Project overview](#1-project-overview)
2. [Repository structure](#2-repository-structure)
3. [Infrastructure and GCP setup](#3-infrastructure-and-gcp-setup)
4. [Data ingestion layer](#4-data-ingestion-layer)
5. [Asset graph (Neo4j)](#5-asset-graph-neo4j)
6. [Agent core (Google ADK + agents-cli)](#6-agent-core-google-adk--agents-cli)
7. [Customer configuration schema](#7-customer-configuration-schema)
8. [Approval and scheduling engine](#8-approval-and-scheduling-engine)
9. [Remediation execution layer](#9-remediation-execution-layer)
10. [Configuration UI (React)](#10-configuration-ui-react)
11. [Approval card UX](#11-approval-card-ux)
12. [Agent Garden publication](#12-agent-garden-publication)
13. [Testing strategy](#13-testing-strategy)
14. [Security and IAM requirements](#14-security-and-iam-requirements)
15. [Open questions and decisions log](#15-open-questions-and-decisions-log)

---

## 1. Project overview

### 1.1 What this agent does

`scc-remediation-agent` is an autonomous security remediation agent published to Google Agent Garden. Customers deploy it into their own GCP organisation via Agent Platform. The agent:

1. Ingests security findings from Security Command Center (SCC), asset metadata from Cloud Asset Inventory, network topology from Network Intelligence Center, and IAM relationships from Policy Analyser.
2. Builds a persistent asset graph (Neo4j) representing all GCP resources, their relationships, labels, and security posture.
3. Triages findings against a customer-defined scope and severity threshold.
4. For each in-scope finding, uses the graph to analyse blast radius, environment classification (prod/dev/staging), dormancy, and downstream dependencies — answering "what happens if I fix this?"
5. Generates a remediation plan with rollback steps.
6. Routes the plan through a human-in-the-loop approval workflow (Google Chat card, PagerDuty, or Jira ticket).
7. On approval, executes the fix using GCP-native APIs (OS Config, Terraform PR, IAM API, Compute API).
8. Verifies closure by re-querying SCC and updates the graph.

### 1.2 Key design constraints

- The agent builds a **full organisation-wide context graph** but only generates and executes fixes for assets within the customer's configured scope.
- **Dry-run mode is the default** on first activation. Execution must be explicitly enabled.
- Every decision the agent makes must be **auditable** — reasoning chains are stored alongside outcomes.
- The agent runs **entirely within the customer's GCP organisation**. No customer data leaves their environment.
- The agent must be **idempotent** — re-running a scan does not re-apply an already-applied fix.

### 1.3 Technology stack

| Layer | Technology |
|---|---|
| Agent framework | Google Agent Development Kit (ADK), Python |
| Agent scaffold | `google-agents-cli` (https://github.com/google/agents-cli) |
| Agent model | Gemini 2.0 Flash (reasoning) + Gemini 2.0 Pro (planning) |
| Graph database | Neo4j Community on GKE (or Spanner Graph for fully-managed) |
| Config storage | Firestore (per-customer config documents) |
| Audit log | BigQuery |
| Job scheduling | Cloud Scheduler + Cloud Tasks |
| Notifications | Google Chat API, PagerDuty Events API v2, Jira REST API |
| Execution — OS patches | GCP OS Config API |
| Execution — misconfigs | Terraform via Cloud Build, or Config Connector |
| Execution — IAM | GCP IAM API |
| Config UI | React + Vite, deployed on Cloud Run |
| Auth (UI) | Google OAuth 2.0 via Identity-Aware Proxy |

---

## 2. Repository structure

```
scc-remediation-agent/
├── agent/                          # Agent core (ADK)
│   ├── main.py                     # Agent entrypoint
│   ├── agents/
│   │   ├── triage_agent.py         # Severity filtering + attack exposure ranking
│   │   ├── impact_agent.py         # Graph traversal + blast radius
│   │   ├── dormancy_agent.py       # Dormancy and traffic checks
│   │   ├── plan_agent.py           # Remediation plan generation
│   │   └── verify_agent.py         # Post-fix SCC verification
│   ├── tools/
│   │   ├── scc_tools.py            # SCC API wrappers
│   │   ├── asset_tools.py          # Asset Inventory API wrappers
│   │   ├── graph_tools.py          # Neo4j query wrappers
│   │   ├── iam_tools.py            # IAM + Policy Analyser wrappers
│   │   ├── network_tools.py        # Network Intelligence wrappers
│   │   ├── osconfig_tools.py       # OS Config API wrappers
│   │   ├── iam_exec_tools.py       # IAM modification execution
│   │   └── approval_tools.py       # Approval workflow dispatch
│   ├── prompts/
│   │   ├── triage.txt
│   │   ├── impact_analysis.txt
│   │   ├── plan_generation.txt
│   │   └── verification.txt
│   └── agent.yaml                  # agents-cli agent definition
├── graph/
│   ├── schema/
│   │   ├── nodes.cypher            # Node label definitions and constraints
│   │   └── relationships.cypher    # Relationship type definitions
│   ├── ingestion/
│   │   ├── asset_ingester.py       # Pulls from Asset Inventory → Neo4j
│   │   ├── finding_ingester.py     # Pulls from SCC → Neo4j
│   │   ├── iam_ingester.py         # Pulls IAM bindings → Neo4j
│   │   └── network_ingester.py     # Pulls VPC topology → Neo4j
│   └── queries/
│       ├── blast_radius.cypher
│       ├── dependency_chain.cypher
│       ├── iam_paths.cypher
│       └── dormancy_check.cypher
├── config/
│   ├── schema.py                   # Pydantic models for customer config
│   ├── validator.py                # Config validation + dry-run preview
│   └── migrations/                 # Config schema versioning
├── scheduler/
│   ├── main.py                     # Cloud Tasks handler
│   ├── windows.py                  # Maintenance window evaluation
│   └── freeze.py                   # Change-freeze detection
├── ui/
│   ├── src/
│   │   ├── pages/
│   │   │   ├── ConfigWizard.tsx    # 5-step configuration wizard
│   │   │   ├── Dashboard.tsx       # Active findings + agent activity
│   │   │   └── AuditLog.tsx        # Decision history
│   │   ├── components/
│   │   │   ├── ScopeStep.tsx
│   │   │   ├── SeverityStep.tsx
│   │   │   ├── ApprovalStep.tsx
│   │   │   ├── ExecutionStep.tsx
│   │   │   └── NotificationStep.tsx
│   │   └── api/
│   │       └── config.ts           # Firestore config read/write
│   └── vite.config.ts
├── terraform/
│   ├── main.tf                     # GCP infrastructure
│   ├── neo4j.tf                    # GKE + Neo4j deployment
│   ├── iam.tf                      # Service account + role bindings
│   └── variables.tf
├── tests/
│   ├── unit/
│   ├── integration/
│   └── fixtures/
│       ├── mock_findings.json
│       └── mock_assets.json
├── agent.yaml                      # agents-cli top-level definition
└── README.md
```

---

## 3. Infrastructure and GCP setup

### 3.1 Required GCP APIs (enable on customer org)

```
securitycenter.googleapis.com
cloudasset.googleapis.com
networkmanagement.googleapis.com
iam.googleapis.com
iamcredentials.googleapis.com
osconfig.googleapis.com
cloudtasks.googleapis.com
cloudscheduler.googleapis.com
firestore.googleapis.com
bigquery.googleapis.com
chat.googleapis.com
container.googleapis.com
cloudbuild.googleapis.com
run.googleapis.com
```

### 3.2 Service account

Create a single service account `scc-remediation-agent@{PROJECT_ID}.iam.gserviceaccount.com` with the following roles bound at **organisation level**:

```
roles/securitycenter.findingsViewer
roles/securitycenter.findingsMuteSetter    # to mute resolved findings
roles/cloudasset.viewer
roles/iam.securityReviewer
roles/networkmanagement.viewer
roles/osconfig.patchJobExecutor
roles/iam.roleViewer
roles/logging.viewer
roles/monitoring.viewer
```

Additional roles at **project level** (only on projects the customer has scoped):

```
roles/iam.securityAdmin                   # only if IAM tightening is enabled
roles/compute.viewer
roles/osconfig.instanceViewer
```

### 3.3 Neo4j on GKE

Deploy Neo4j Community Edition using the Helm chart. Key settings:

```yaml
# neo4j/values.yaml
neo4j:
  name: asset-graph
  resources:
    requests:
      memory: "4Gi"
      cpu: "2"
  storage:
    data:
      requests:
        storage: 100Gi
  config:
    dbms.memory.heap.initial_size: "2G"
    dbms.memory.heap.max_size: "4G"
    dbms.memory.pagecache.size: "1G"
```

Expose Neo4j only on a private ClusterIP — do not create an external LoadBalancer. The agent connects via the cluster-internal DNS name `neo4j.neo4j.svc.cluster.local:7687`.

### 3.4 Firestore collections

```
/configs/{customer_id}                    # CustomerConfig document
/configs/{customer_id}/versions/{v}       # Config version history
/findings/{finding_id}                    # Active finding + agent state
/approvals/{approval_id}                  # Approval request + response
/audit/{entry_id}                         # Audit log (also streamed to BigQuery)
```

---

## 4. Data ingestion layer

### 4.1 Ingestion schedule

All ingestion jobs run via Cloud Scheduler:

| Job | Schedule | Description |
|---|---|---|
| `asset-full-sync` | Every 6 hours | Full Asset Inventory export → graph rebuild |
| `finding-sync` | Every 15 minutes | Delta SCC findings since last run |
| `iam-sync` | Every 1 hour | IAM binding refresh |
| `network-sync` | Every 6 hours | VPC topology refresh |

Real-time finding ingestion also subscribes to an SCC Pub/Sub notification channel for immediate processing of new critical findings.

### 4.2 SCC findings ingestion (`graph/ingestion/finding_ingester.py`)

```python
from google.cloud import securitycenter_v1
from typing import Iterator

def list_active_findings(
    org_id: str,
    severity_filter: list[str],   # e.g. ["CRITICAL", "HIGH"]
    page_size: int = 1000
) -> Iterator[dict]:
    """
    Yields normalised finding dicts from SCC.
    Applies severity filter and excludes muted findings.
    """
    client = securitycenter_v1.SecurityCenterClient()
    parent = f"organizations/{org_id}/sources/-"

    sev_expr = " OR ".join(f'severity="{s}"' for s in severity_filter)
    filter_str = f'state="ACTIVE" AND NOT mute="MUTED" AND ({sev_expr})'

    request = securitycenter_v1.ListFindingsRequest(
        parent=parent,
        filter=filter_str,
        page_size=page_size,
        field_mask="name,resourceName,category,severity,findingClass,"
                   "vulnerability,externalSystems,attackExposure,"
                   "remediation,createTime,eventTime"
    )

    for result in client.list_findings(request=request):
        f = result.finding
        yield {
            "finding_id": f.name.split("/")[-1],
            "full_name": f.name,
            "resource_name": f.resource_name,
            "category": f.category,
            "severity": f.severity.name,
            "finding_class": f.finding_class.name,
            "cve_ids": [v.cve.id for v in f.vulnerability.cve_ids] if f.vulnerability else [],
            "cvss_score": f.vulnerability.cvss.score if f.vulnerability and f.vulnerability.cvss else None,
            "attack_exposure_score": f.attack_exposure.score if f.attack_exposure else 0.0,
            "attack_exposure_state": f.attack_exposure.state.name if f.attack_exposure else "UNKNOWN",
            "remediation_text": f.remediation.instructions if f.remediation else "",
            "remediation_uri": f.remediation.uri if f.remediation else "",
            "event_time": f.event_time.isoformat(),
        }
```

### 4.3 Asset Inventory ingestion (`graph/ingestion/asset_ingester.py`)

```python
from google.cloud import asset_v1

ASSET_TYPES = [
    "compute.googleapis.com/Instance",
    "compute.googleapis.com/Disk",
    "compute.googleapis.com/Network",
    "compute.googleapis.com/Subnetwork",
    "compute.googleapis.com/Firewall",
    "container.googleapis.com/Cluster",
    "sqladmin.googleapis.com/Instance",
    "storage.googleapis.com/Bucket",
    "iam.googleapis.com/ServiceAccount",
    "cloudresourcemanager.googleapis.com/Project",
    "cloudresourcemanager.googleapis.com/Folder",
]

def export_assets(org_id: str) -> list[dict]:
    """
    Exports all assets across the org.
    Returns list of normalised asset dicts with labels, location, and ancestry.
    """
    client = asset_v1.AssetServiceClient()
    assets = []

    request = asset_v1.ListAssetsRequest(
        parent=f"organizations/{org_id}",
        asset_types=ASSET_TYPES,
        content_type=asset_v1.ContentType.RESOURCE,
        page_size=1000,
    )

    for asset in client.list_assets(request=request):
        resource = asset.resource.data
        assets.append({
            "asset_name": asset.name,
            "asset_type": asset.asset_type,
            "project": _extract_project(asset.name),
            "location": resource.get("location") or resource.get("region") or "global",
            "labels": dict(resource.get("labels", {})),
            "status": resource.get("status", "RUNNING"),
            "create_time": resource.get("creationTimestamp") or resource.get("createTime"),
            "ancestors": list(asset.ancestors),
            "raw": dict(resource),
        })

    return assets

def _extract_project(asset_name: str) -> str:
    parts = asset_name.split("/")
    if "projects" in parts:
        idx = parts.index("projects")
        return parts[idx + 1]
    return "unknown"
```

### 4.4 Relationship export

After ingesting assets, call the Asset Inventory relationships API to get:

- `INSTANCE_TO_INSTANCEGROUP`
- `INSTANCE_TO_NETWORK`
- `BUCKET_TO_PROJECT`
- `TABLE_TO_DATASET`
- `DISK_TO_INSTANCE`

```python
def export_relationships(org_id: str) -> list[dict]:
    client = asset_v1.AssetServiceClient()
    relationships = []

    request = asset_v1.ListAssetsRequest(
        parent=f"organizations/{org_id}",
        asset_types=ASSET_TYPES,
        content_type=asset_v1.ContentType.RELATIONSHIP,
        page_size=1000,
    )

    for asset in client.list_assets(request=request):
        for rel in asset.related_assets.relationship_attributes:
            for related in asset.related_assets.related_assets:
                relationships.append({
                    "source": asset.name,
                    "target": related.asset,
                    "relationship_type": rel.relationship_type,
                })

    return relationships
```

---

## 5. Asset graph (Neo4j)

### 5.1 Node schema (`graph/schema/nodes.cypher`)

```cypher
// Constraints — run once at setup
CREATE CONSTRAINT resource_name IF NOT EXISTS
  FOR (r:Resource) REQUIRE r.asset_name IS UNIQUE;

CREATE CONSTRAINT finding_id IF NOT EXISTS
  FOR (f:Finding) REQUIRE f.finding_id IS UNIQUE;

CREATE CONSTRAINT project_id IF NOT EXISTS
  FOR (p:Project) REQUIRE p.project_id IS UNIQUE;
```

Node labels and properties:

```
:Resource {
  asset_name: String,           // full GCP resource name
  asset_type: String,           // e.g. "compute.googleapis.com/Instance"
  short_name: String,           // last segment of asset_name
  project: String,
  location: String,
  env: String,                  // derived from labels: prod | dev | staging | unknown
  team: String,                 // from label team=
  data_class: String,           // from label data-class=
  maint_window: String,         // from label maint-window=
  owner_email: String,          // from label owner=
  status: String,               // RUNNING | TERMINATED | STOPPED
  dormancy_score: Float,        // 0.0 (active) to 1.0 (fully dormant)
  last_activity: DateTime,
  labels: Map,                  // all raw labels
  create_time: DateTime,
  in_scope: Boolean,            // true if matches customer config scope
  last_synced: DateTime
}

:Finding {
  finding_id: String,
  full_name: String,
  category: String,
  severity: String,             // CRITICAL | HIGH | MEDIUM | LOW
  finding_class: String,        // VULNERABILITY | MISCONFIGURATION | etc.
  cve_ids: [String],
  cvss_score: Float,
  attack_exposure_score: Float,
  attack_exposure_state: String,
  remediation_text: String,
  remediation_uri: String,
  state: String,                // ACTIVE | REMEDIATED | DEFERRED | MUTED
  plan_id: String,              // FK to remediation plan
  event_time: DateTime,
  last_synced: DateTime
}

:Project {
  project_id: String,
  project_name: String,
  folder_id: String,
  org_id: String,
  in_scope: Boolean
}
```

### 5.2 Relationship schema (`graph/schema/relationships.cypher`)

```cypher
// Resource → Project
(:Resource)-[:BELONGS_TO]->(:Project)

// Finding → Resource
(:Finding)-[:AFFECTS]->(:Resource)

// Resource ↔ Resource
(:Resource)-[:CONNECTS_TO {
  protocol: String,
  port: String,
  direction: String,            // INGRESS | EGRESS
  firewall_rule: String
}]->(:Resource)

(:Resource)-[:ROUTES_TRAFFIC_TO]->(:Resource)

(:Resource)-[:DEPENDS_ON {
  dependency_type: String       // SERVICE_MESH | DNS | SHARED_SA
}]->(:Resource)

(:Resource)-[:HOSTED_BY]->(:Resource)  // Pod → Node, VM → MIG

// IAM relationships
(:Resource)-[:GRANTS_ACCESS_TO {
  role: String,
  principal: String,
  principal_type: String        // serviceAccount | user | group
}]->(:Resource)

(:Resource)-[:USES_SERVICE_ACCOUNT {
  email: String
}]->(:Resource)
```

### 5.3 Key graph queries (`graph/queries/`)

**Blast radius traversal** (`blast_radius.cypher`):
```cypher
// Find all resources reachable from a vulnerable resource within 3 hops
MATCH path = (vuln:Resource {asset_name: $asset_name})-
  [:CONNECTS_TO|ROUTES_TRAFFIC_TO|DEPENDS_ON|GRANTS_ACCESS_TO*1..3]->(downstream:Resource)
WHERE downstream.in_scope = true
RETURN downstream.asset_name AS name,
       downstream.env AS env,
       downstream.data_class AS data_class,
       length(path) AS hops,
       [r in relationships(path) | type(r)] AS relationship_types
ORDER BY hops ASC, downstream.env DESC
```

**IAM lateral movement paths** (`iam_paths.cypher`):
```cypher
// Find principals that have access to both the vulnerable resource and prod resources
MATCH (vuln:Resource {asset_name: $asset_name})<-[:GRANTS_ACCESS_TO]-(sa:Resource)
MATCH (sa)-[:GRANTS_ACCESS_TO]->(prod:Resource {env: "prod"})
WHERE prod.asset_name <> $asset_name
RETURN sa.asset_name AS service_account,
       collect(DISTINCT prod.asset_name) AS reachable_prod_resources,
       count(DISTINCT prod) AS prod_blast_count
```

**Dormancy check** (`dormancy_check.cypher`):
```cypher
MATCH (r:Resource {asset_name: $asset_name})
RETURN r.dormancy_score AS dormancy_score,
       r.last_activity AS last_activity,
       r.status AS status,
       CASE
         WHEN r.dormancy_score > 0.8 THEN "DORMANT"
         WHEN r.dormancy_score > 0.4 THEN "PERIODIC"
         ELSE "ACTIVE"
       END AS dormancy_class
```

### 5.4 Dormancy scoring

Dormancy score is computed during ingestion and stored on the `:Resource` node:

```python
def compute_dormancy_score(asset_name: str, project_id: str) -> float:
    """
    Returns float 0.0 (active) to 1.0 (fully dormant).
    Combines: last log entry, monitoring metrics, VPC flow bytes.
    """
    from google.cloud import monitoring_v3
    import datetime

    now = datetime.datetime.utcnow()
    cutoff_30d = now - datetime.timedelta(days=30)

    # Check Cloud Monitoring: received_bytes_count or requests
    # Returns 0 if any metric > 0 in last 30d, 1.0 if no data at all
    # Implementation: query monitoring API for relevant metric type
    # This is a stub — full implementation uses monitoring_v3 MetricServiceClient

    score_components = []

    # Component 1: resource status
    if _get_resource_status(asset_name) in ["TERMINATED", "STOPPED"]:
        score_components.append(1.0)
    else:
        score_components.append(0.0)

    # Component 2: last log activity (Cloud Logging)
    days_since_log = _days_since_last_log(asset_name, project_id)
    score_components.append(min(days_since_log / 30.0, 1.0))

    # Component 3: network traffic (flow logs)
    has_traffic = _has_recent_traffic(asset_name, project_id, days=30)
    score_components.append(0.0 if has_traffic else 1.0)

    return sum(score_components) / len(score_components)
```

---

## 6. Agent core (Google ADK + agents-cli)

### 6.1 `agent.yaml` (agents-cli definition)

```yaml
name: scc-remediation-agent
display_name: SCC Remediation Agent
version: 1.0.0
description: |
  Autonomous GCP security remediation agent. Ingests SCC findings,
  analyses blast radius via asset graph, generates remediation plans,
  and executes approved fixes using GCP-native APIs.
author: your-org
category: security
tags: [security, scc, remediation, gcp, vulnerability-management]

model:
  reasoning: gemini-2.0-flash
  planning: gemini-2.0-pro

entrypoint: agent/main.py

tools:
  - name: list_active_findings
    module: agent/tools/scc_tools.py
  - name: get_finding_detail
    module: agent/tools/scc_tools.py
  - name: get_asset_metadata
    module: agent/tools/asset_tools.py
  - name: query_blast_radius
    module: agent/tools/graph_tools.py
  - name: query_iam_paths
    module: agent/tools/graph_tools.py
  - name: check_dormancy
    module: agent/tools/graph_tools.py
  - name: get_network_exposure
    module: agent/tools/network_tools.py
  - name: check_effective_permissions
    module: agent/tools/iam_tools.py
  - name: generate_patch_job
    module: agent/tools/osconfig_tools.py
  - name: dispatch_approval_request
    module: agent/tools/approval_tools.py
  - name: record_audit_entry
    module: agent/tools/audit_tools.py
  - name: mute_resolved_finding
    module: agent/tools/scc_tools.py

triggers:
  - type: schedule
    cron: "*/15 * * * *"
    description: Poll for new findings
  - type: pubsub
    topic: scc-findings-notifications
    description: Real-time SCC finding notifications

config:
  source: firestore
  collection: configs
  key_from_env: CUSTOMER_ID
```

### 6.2 Main agent loop (`agent/main.py`)

```python
import asyncio
from google.adk.agents import Agent
from agents.triage_agent import TriageAgent
from agents.impact_agent import ImpactAgent
from agents.dormancy_agent import DormancyAgent
from agents.plan_agent import PlanAgent
from agents.verify_agent import VerifyAgent
from config.schema import CustomerConfig
from config.loader import load_config
import os

async def run_remediation_cycle(config: CustomerConfig):
    """
    Main orchestration loop. Called on schedule or Pub/Sub trigger.
    """
    print(f"[cycle] Starting remediation cycle for customer {config.customer_id}")

    # Step 1: Triage
    triage = TriageAgent(config)
    prioritised_findings = await triage.run()
    print(f"[triage] {len(prioritised_findings)} findings in scope after filtering")

    for finding in prioritised_findings:
        print(f"[finding] Processing {finding['finding_id']} ({finding['severity']}) on {finding['resource_name']}")

        # Step 2: Impact analysis
        impact = ImpactAgent(config)
        impact_result = await impact.analyse(finding)

        # Step 3: Dormancy check
        dormancy = DormancyAgent(config)
        dormancy_result = await dormancy.check(finding['resource_name'])

        # Step 4: Generate remediation plan
        planner = PlanAgent(config)
        plan = await planner.generate(finding, impact_result, dormancy_result)

        if plan is None:
            print(f"[plan] No actionable plan for {finding['finding_id']} — skipping")
            continue

        # Step 5: Route to approval or auto-approve
        if _is_auto_approve_eligible(finding, impact_result, dormancy_result, config):
            print(f"[approve] Auto-approving {finding['finding_id']}")
            await _schedule_execution(plan, delay_minutes=0, config=config)
        else:
            await _dispatch_for_approval(plan, finding, impact_result, config)

async def _dispatch_for_approval(plan, finding, impact, config: CustomerConfig):
    from tools.approval_tools import dispatch_approval_request
    approval_id = await dispatch_approval_request(
        plan=plan,
        finding=finding,
        impact=impact,
        config=config,
        channels=config.approval_policy.notification_channels,
    )
    print(f"[approval] Dispatched approval request {approval_id}")

def _is_auto_approve_eligible(finding, impact, dormancy, config: CustomerConfig) -> bool:
    """
    Returns True if the finding can be auto-approved based on config policy.
    Conditions (all must be true):
    - auto_approve_enabled is True in config
    - blast radius is LOW (0 prod downstream dependencies)
    - dormancy class is DORMANT or PERIODIC
    - no change freeze active
    - dry_run mode is False
    """
    if config.dry_run:
        return False
    if not config.approval_policy.auto_approve_enabled:
        return False
    if impact.get("prod_blast_count", 0) > 0:
        return False
    if dormancy.get("dormancy_class") == "ACTIVE":
        return False
    from scheduler.freeze import is_change_frozen
    if is_change_frozen(finding["resource_name"], config):
        return False
    return True

if __name__ == "__main__":
    customer_id = os.environ["CUSTOMER_ID"]
    config = load_config(customer_id)
    asyncio.run(run_remediation_cycle(config))
```

### 6.3 Triage agent (`agent/agents/triage_agent.py`)

```python
from tools.scc_tools import list_active_findings
from tools.graph_tools import get_resource_scope_status

class TriageAgent:
    def __init__(self, config):
        self.config = config

    async def run(self) -> list[dict]:
        """
        Fetches active findings, filters to in-scope assets and
        severity threshold, deduplicates, and ranks by attack exposure.
        """
        cfg = self.config
        findings = list(list_active_findings(
            org_id=cfg.org_id,
            severity_filter=cfg.severity_threshold.to_api_values(),
        ))

        # Filter to in-scope resources
        in_scope = []
        for f in findings:
            scope_status = get_resource_scope_status(
                asset_name=f["resource_name"],
                scope_config=cfg.scope,
            )
            if scope_status["in_scope"]:
                f["scope_metadata"] = scope_status
                in_scope.append(f)

        # Deduplicate by (resource_name, category, cve_ids)
        if cfg.filters.deduplicate_across_scanners:
            in_scope = _deduplicate(in_scope)

        # Remove accepted risks
        if cfg.filters.exclude_accepted_risks:
            in_scope = [f for f in in_scope if not f.get("muted")]

        # Rank by attack exposure score descending
        in_scope.sort(key=lambda f: f.get("attack_exposure_score", 0.0), reverse=True)

        # Drop findings with no exposure path if configured
        if cfg.filters.require_active_exposure_path:
            in_scope = [
                f for f in in_scope
                if f.get("attack_exposure_state") == "EXPOSED"
                or f.get("attack_exposure_score", 0) > 0
            ]

        return in_scope

def _deduplicate(findings: list[dict]) -> list[dict]:
    seen = set()
    result = []
    for f in findings:
        key = (f["resource_name"], f["category"], tuple(sorted(f.get("cve_ids", []))))
        if key not in seen:
            seen.add(key)
            result.append(f)
    return result
```

### 6.4 Impact agent (`agent/agents/impact_agent.py`)

```python
from tools.graph_tools import query_blast_radius, query_iam_paths, get_resource_metadata
from tools.network_tools import get_network_exposure

class ImpactAgent:
    def __init__(self, config):
        self.config = config

    async def analyse(self, finding: dict) -> dict:
        asset_name = finding["resource_name"]

        # Graph traversal
        downstream = query_blast_radius(asset_name, max_hops=3)
        iam_paths = query_iam_paths(asset_name)
        metadata = get_resource_metadata(asset_name)
        network = get_network_exposure(asset_name, self.config.org_id)

        prod_downstream = [r for r in downstream if r.get("env") == "prod"]
        pii_downstream = [r for r in downstream if r.get("data_class") == "pii"]

        blast_level = "LOW"
        if len(prod_downstream) > 0 or metadata.get("env") == "prod":
            blast_level = "MEDIUM"
        if len(prod_downstream) > 3 or pii_downstream:
            blast_level = "HIGH"
        if len(prod_downstream) > 10:
            blast_level = "CRITICAL"

        return {
            "asset_name": asset_name,
            "asset_env": metadata.get("env", "unknown"),
            "asset_team": metadata.get("team", "unknown"),
            "asset_owner": metadata.get("owner_email", ""),
            "blast_level": blast_level,
            "total_downstream": len(downstream),
            "prod_blast_count": len(prod_downstream),
            "pii_blast_count": len(pii_downstream),
            "downstream_resources": downstream[:20],   # cap for prompt context
            "iam_lateral_paths": iam_paths[:10],
            "internet_exposed": network.get("internet_exposed", False),
            "network_exposure_details": network,
        }
```

### 6.5 Plan agent (`agent/agents/plan_agent.py`)

The plan agent uses Gemini to generate a structured remediation plan. It is given the finding, impact analysis, dormancy result, and the SCC remediation guidance.

```python
import json
from google.adk.agents import LlmAgent
from config.schema import RemediationMode

PLAN_PROMPT_TEMPLATE = """
You are a GCP security remediation specialist. Generate a detailed remediation plan.

## Finding
{finding_json}

## Asset context
{impact_json}

## Dormancy
{dormancy_json}

## SCC remediation guidance
{remediation_text}

## Customer config
Enabled remediation modes: {enabled_modes}
Dry run: {dry_run}

## Instructions
Generate a JSON remediation plan with the following structure:
{{
  "plan_id": "<uuid>",
  "finding_id": "<finding_id>",
  "asset_name": "<asset_name>",
  "remediation_type": "OS_PATCH | MISCONFIGURATION | IAM | FIREWALL",
  "summary": "<one sentence>",
  "risk_assessment": "<2-3 sentences on blast radius and change risk>",
  "steps": [
    {{
      "order": 1,
      "action": "<description>",
      "api_call": "<gcloud command or API>",
      "expected_outcome": "<what happens>",
      "verification": "<how to confirm success>"
    }}
  ],
  "rollback_steps": [
    {{
      "order": 1,
      "action": "<rollback action>",
      "api_call": "<gcloud command or API>"
    }}
  ],
  "estimated_downtime_minutes": 0,
  "requires_reboot": false,
  "confidence": "HIGH | MEDIUM | LOW",
  "change_window_required": true
}}

Return only valid JSON. No preamble or explanation.
"""

class PlanAgent:
    def __init__(self, config):
        self.config = config

    async def generate(self, finding: dict, impact: dict, dormancy: dict) -> dict | None:
        enabled_modes = [m.value for m in self.config.execution.enabled_modes]

        # Check if we have a mode for this finding type
        finding_class = finding.get("finding_class", "")
        if not _has_applicable_mode(finding_class, enabled_modes):
            return None

        prompt = PLAN_PROMPT_TEMPLATE.format(
            finding_json=json.dumps(finding, indent=2, default=str),
            impact_json=json.dumps(impact, indent=2),
            dormancy_json=json.dumps(dormancy, indent=2),
            remediation_text=finding.get("remediation_text", "No guidance available."),
            enabled_modes=", ".join(enabled_modes),
            dry_run=self.config.dry_run,
        )

        agent = LlmAgent(model="gemini-2.0-pro")
        response = await agent.generate(prompt)
        plan = json.loads(response.text)
        plan["dry_run"] = self.config.dry_run
        return plan

def _has_applicable_mode(finding_class: str, enabled_modes: list[str]) -> bool:
    mapping = {
        "VULNERABILITY": "OS_PATCH",
        "MISCONFIGURATION": "MISCONFIGURATION",
        "SCC_ERROR": None,
        "OBSERVATION": None,
    }
    required = mapping.get(finding_class)
    return required is not None and required in enabled_modes
```

---

## 7. Customer configuration schema

### 7.1 Pydantic models (`config/schema.py`)

```python
from pydantic import BaseModel, Field, validator
from typing import Optional
from enum import Enum
import datetime

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
    display_name: str
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

    class Config:
        use_enum_values = True
```

### 7.2 Config versioning

Every config save increments the `version` field and writes the previous version to `/configs/{customer_id}/versions/{version}` in Firestore. Never overwrite history. Expose a diff API endpoint that compares two versions.

### 7.3 Config validation (`config/validator.py`)

```python
async def validate_and_preview(config: CustomerConfig) -> dict:
    """
    Runs a dry simulation of the config against current findings and assets.
    Returns a preview dict for display in the UI before activation.
    Returns errors if config is invalid (e.g., no approvers for critical findings).
    """
    errors = []
    warnings = []

    # Validate: critical findings must have an approver
    has_critical_approver = any(
        "CRITICAL" in a.severity_levels for a in config.approval_policy.approvers
    )
    if not has_critical_approver and config.severity_threshold in ["CRITICAL_ONLY", "HIGH_PLUS"]:
        errors.append("No approver configured for CRITICAL severity findings.")

    # Validate: auto-approve tier requires auto_approve_enabled
    auto_tiers = [t for t in config.approval_policy.tiers if t.auto_approve_eligible]
    if auto_tiers and not config.approval_policy.auto_approve_enabled:
        warnings.append("Auto-approve tiers defined but auto_approve_enabled is False.")

    # Preview: count in-scope assets
    from graph.queries import count_in_scope_assets
    asset_count = await count_in_scope_assets(config.scope, config.org_id)

    # Preview: count actionable findings
    from tools.scc_tools import list_active_findings
    findings = list(list_active_findings(config.org_id, config.severity_threshold.to_api_values()))
    in_scope_findings = [f for f in findings if config.scope.matches_asset({"project": _extract_project(f["resource_name"]), "labels": {}})]
    auto_approve_count = 0   # would need graph query to estimate

    return {
        "valid": len(errors) == 0,
        "errors": errors,
        "warnings": warnings,
        "preview": {
            "assets_in_scope": asset_count,
            "active_findings_in_scope": len(in_scope_findings),
            "estimated_auto_approve": auto_approve_count,
            "dry_run_active": config.dry_run,
        }
    }
```

---

## 8. Approval and scheduling engine

### 8.1 Approval request dispatch (`agent/tools/approval_tools.py`)

```python
import uuid
import json
from google.cloud import firestore
from googleapiclient.discovery import build

async def dispatch_approval_request(
    plan: dict,
    finding: dict,
    impact: dict,
    config,
    channels: list[str],
) -> str:
    """
    Creates an approval record in Firestore and sends the card to all channels.
    Returns the approval_id.
    """
    approval_id = str(uuid.uuid4())
    db = firestore.Client()

    approval_doc = {
        "approval_id": approval_id,
        "plan_id": plan["plan_id"],
        "finding_id": finding["finding_id"],
        "asset_name": finding["resource_name"],
        "severity": finding["severity"],
        "blast_level": impact["blast_level"],
        "status": "PENDING",
        "created_at": firestore.SERVER_TIMESTAMP,
        "expires_at": _compute_expiry(finding["severity"], config),
        "channels_notified": channels,
        "plan_summary": plan["summary"],
        "rollback_steps": plan["rollback_steps"],
    }

    db.collection("approvals").document(approval_id).set(approval_doc)

    # Dispatch to each configured channel
    for channel in channels:
        if channel == "google_chat" and config.notifications.google_chat_space:
            await _send_chat_card(approval_id, plan, finding, impact, config)
        if channel == "pagerduty" and config.notifications.pagerduty_service_key:
            await _send_pagerduty_alert(approval_id, plan, finding, impact, config)
        if channel == "jira" and config.notifications.jira_project_key:
            await _create_jira_ticket(approval_id, plan, finding, impact, config)

    # Schedule auto-escalation
    _schedule_escalation(approval_id, config)

    return approval_id

async def _send_chat_card(approval_id, plan, finding, impact, config):
    """Sends a structured Google Chat card with approve/reject/defer buttons."""
    service = build("chat", "v1")

    severity_color = {
        "CRITICAL": "#E24B4A",
        "HIGH": "#BA7517",
        "MEDIUM": "#378ADD",
        "LOW": "#639922",
    }.get(finding["severity"], "#888780")

    card = {
        "cardsV2": [{
            "cardId": f"approval-{approval_id}",
            "card": {
                "header": {
                    "title": f"Remediation approval required",
                    "subtitle": f"{finding['severity']} · {finding['category']}",
                },
                "sections": [
                    {
                        "widgets": [
                            {"textParagraph": {"text": f"<b>Asset:</b> {finding['resource_name']}"}},
                            {"textParagraph": {"text": f"<b>Finding:</b> {plan['summary']}"}},
                            {"textParagraph": {"text": f"<b>Blast radius:</b> {impact['blast_level']} · {impact['prod_blast_count']} prod dependencies"}},
                            {"textParagraph": {"text": f"<b>Environment:</b> {impact['asset_env']} · Team: {impact['asset_team']}"}},
                            {"textParagraph": {"text": f"<b>Risk assessment:</b> {plan['risk_assessment']}"}},
                            {"textParagraph": {"text": f"<b>Downtime:</b> {plan['estimated_downtime_minutes']} min · Reboot: {'Yes' if plan['requires_reboot'] else 'No'}"}},
                        ]
                    },
                    {
                        "header": "Rollback plan",
                        "widgets": [
                            {"textParagraph": {"text": "\n".join(f"{s['order']}. {s['action']}" for s in plan["rollback_steps"][:3])}}
                        ]
                    },
                    {
                        "widgets": [{
                            "buttonList": {
                                "buttons": [
                                    {
                                        "text": "Approve",
                                        "onClick": {"action": {"function": "approve_remediation", "parameters": [{"key": "approval_id", "value": approval_id}]}}
                                    },
                                    {
                                        "text": "Reject",
                                        "onClick": {"action": {"function": "reject_remediation", "parameters": [{"key": "approval_id", "value": approval_id}]}}
                                    },
                                    {
                                        "text": "Defer to window",
                                        "onClick": {"action": {"function": "defer_remediation", "parameters": [{"key": "approval_id", "value": approval_id}]}}
                                    },
                                ]
                            }
                        }]
                    }
                ]
            }
        }]
    }

    service.spaces().messages().create(
        parent=config.notifications.google_chat_space,
        body=card,
    ).execute()
```

### 8.2 Approval webhook handler

Deploy a Cloud Run service to receive approval responses from Google Chat interactive cards, PagerDuty webhooks, and Jira webhooks. On response:

1. Update the Firestore approval document (`status: APPROVED | REJECTED | DEFERRED`).
2. If APPROVED: enqueue a Cloud Tasks job with the plan payload.
3. If DEFERRED: compute the next maintenance window and schedule a delayed Cloud Tasks job.
4. Write an audit entry.

### 8.3 Maintenance window evaluation (`scheduler/windows.py`)

```python
import datetime
import pytz
from config.schema import MaintenanceWindow, CustomerConfig

def next_maintenance_window(config: CustomerConfig, asset_name: str) -> datetime.datetime:
    """
    Returns the UTC datetime of the start of the next maintenance window
    for the given asset. Checks resource label first, falls back to default.
    """
    from graph.queries import get_resource_maint_window
    resource_window = get_resource_maint_window(asset_name)
    window = resource_window or config.approval_policy.default_maintenance_window
    return _compute_next_window(window)

def _compute_next_window(window: MaintenanceWindow) -> datetime.datetime:
    tz = pytz.timezone(window.timezone)
    now = datetime.datetime.now(tz)
    start_h, start_m = map(int, window.start_time_utc.split(":"))

    for days_ahead in range(8):
        candidate = now + datetime.timedelta(days=days_ahead)
        if candidate.weekday() in window.days_of_week:
            candidate = candidate.replace(
                hour=start_h, minute=start_m, second=0, microsecond=0
            )
            if candidate > now:
                return candidate.astimezone(pytz.utc).replace(tzinfo=None)

    raise ValueError("No valid maintenance window found in next 7 days")
```

### 8.4 Change freeze detection (`scheduler/freeze.py`)

```python
def is_change_frozen(asset_name: str, config) -> bool:
    """
    Returns True if a change freeze is in effect for this asset.
    Checks (in order):
    1. Resource label change-freeze=true
    2. Project-level label change-freeze=true
    3. Config-level global freeze toggle
    """
    from graph.queries import get_resource_labels
    labels = get_resource_labels(asset_name)
    if labels.get("change-freeze") == "true":
        return True

    project_labels = get_resource_labels(_get_project_resource(asset_name))
    if project_labels.get("change-freeze") == "true":
        return True

    # Future: ITSM/calendar integration check here

    return False
```

---

## 9. Remediation execution layer

### 9.1 OS patch execution (`agent/tools/osconfig_tools.py`)

```python
from google.cloud import osconfig_v1

def create_patch_job(
    project_id: str,
    asset_name: str,
    cve_ids: list[str],
    config,
) -> str:
    """
    Creates a GCP OS Config patch job targeting the specific instance.
    Returns the patch job name.
    """
    client = osconfig_v1.OsConfigServiceClient()

    instance_filter = osconfig_v1.PatchInstanceFilter(
        instances=[asset_name]
    )

    patch_config = osconfig_v1.PatchConfig(
        reboot_config=osconfig_v1.PatchConfig.RebootConfig.DEFAULT,
        apt=osconfig_v1.AptSettings(
            type=osconfig_v1.AptSettings.Type.UPGRADE,
            excludes=[],
        ),
        yum=osconfig_v1.YumSettings(
            security=True,
            minimal=False,
        ),
        windows_update=osconfig_v1.WindowsUpdateSettings(
            classifications=[
                osconfig_v1.WindowsUpdateSettings.Classification.CRITICAL,
                osconfig_v1.WindowsUpdateSettings.Classification.SECURITY,
            ]
        ),
    )

    rollout = osconfig_v1.PatchRollout(
        mode=osconfig_v1.PatchRollout.Mode.ZONE_BY_ZONE,
        disruption_budget=osconfig_v1.FixedOrPercent(percent=50),
    )

    request = osconfig_v1.CreatePatchJobRequest(
        parent=f"projects/{project_id}",
        patch_job=osconfig_v1.PatchJob(
            display_name=f"scc-auto-patch-{cve_ids[0] if cve_ids else 'general'}",
            description=f"Automated patch by scc-remediation-agent. CVEs: {', '.join(cve_ids)}",
            instance_filter=instance_filter,
            patch_config=patch_config,
            rollout=rollout,
            dry_run=config.dry_run,
        )
    )

    job = client.create_patch_job(request=request)
    return job.name
```

### 9.2 Terraform PR for misconfigurations

For misconfiguration findings, the plan agent generates a Terraform diff. The execution layer:

1. Clones the customer's GitOps repo (configured in `execution.gitops_repo`).
2. Creates a branch `scc-fix/{finding_id}`.
3. Applies the generated Terraform diff.
4. Runs `terraform plan` via Cloud Build and attaches the output to the PR.
5. Opens a PR with the plan summary and risk assessment in the description.
6. If the customer has auto-merge enabled and dry_run is False, merges after plan passes CI.

Cloud Build trigger YAML for the Terraform PR pipeline:

```yaml
# cloudbuild-terraform-pr.yaml
steps:
  - name: 'hashicorp/terraform:latest'
    entrypoint: 'sh'
    args:
      - '-c'
      - |
        terraform init
        terraform plan -out=tfplan 2>&1 | tee /workspace/plan_output.txt
        terraform show -json tfplan > /workspace/plan.json

  - name: 'gcr.io/cloud-builders/gcloud'
    entrypoint: 'python3'
    args: ['scripts/post_plan_to_pr.py']
    env:
      - 'PR_URL=$_PR_URL'
      - 'PLAN_OUTPUT_PATH=/workspace/plan_output.txt'
```

### 9.3 Post-fix verification (`agent/agents/verify_agent.py`)

```python
import asyncio
from tools.scc_tools import get_finding_detail, mute_resolved_finding
from tools.graph_tools import update_resource_finding_state

class VerifyAgent:
    def __init__(self, config):
        self.config = config

    async def verify(self, plan: dict, max_retries: int = 6, retry_interval_seconds: int = 300) -> dict:
        """
        Polls SCC to confirm the finding is resolved.
        Retries up to max_retries times with retry_interval_seconds between each.
        """
        finding_id = plan["finding_id"]

        for attempt in range(max_retries):
            await asyncio.sleep(retry_interval_seconds if attempt > 0 else 60)

            finding = get_finding_detail(finding_id, self.config.org_id)
            state = finding.get("state", "ACTIVE")

            if state != "ACTIVE":
                # Success: update graph, mute finding, write audit entry
                update_resource_finding_state(
                    asset_name=plan["asset_name"],
                    finding_id=finding_id,
                    new_state="REMEDIATED",
                )
                if not self.config.dry_run:
                    mute_resolved_finding(finding_id, self.config.org_id)

                return {"success": True, "final_state": state, "attempts": attempt + 1}

        # Failure: create escalation
        return {
            "success": False,
            "final_state": "ACTIVE",
            "attempts": max_retries,
            "escalation_required": True,
        }
```

---

## 10. Configuration UI (React)

### 10.1 Overview

A 5-step wizard deployed on Cloud Run, protected by Identity-Aware Proxy. Reads and writes to Firestore via a backend API (Cloud Run Python service). The wizard steps are:

1. **Scope** — target projects, include/exclude label filters, live asset count preview
2. **Severity & filters** — threshold selector, toggle filters, active exposure path requirement
3. **Approval policy** — per-tier configuration, approver management, maintenance window
4. **Execution** — enabled remediation modes, dry-run toggle, GitOps repo config
5. **Notifications** — channel toggles and connection config

### 10.2 Key UI behaviours

**Scope preview** — after any change to project IDs or label filters, debounce 500ms then call the backend `/api/config/preview-scope` endpoint. Display asset count and show a CEL-like query string showing the effective filter.

**Config validation before save** — on "Save & continue" in each step, call `/api/config/validate` with the partial config. Block progression if there are errors; show warnings with acknowledgement.

**Activation dry-run report** — when the user clicks "Activate agent" on step 5, show a modal with the simulation results: how many findings would be actioned, how many auto-approved, who would receive approval requests. The user must confirm before activation.

**Dry-run banner** — when dry_run is True, show a persistent amber banner at the top of the wizard and dashboard: "Dry-run mode active. The agent generates plans but will not execute any changes."

**Config diff on edit** — when editing an existing config, show a change summary before saving: "You are changing severity threshold from HIGH+ to CRITICAL ONLY. This will reduce active findings from 34 to 12."

**Owner label warning** — if the asset inventory contains resources without an `owner=` label that would be in scope, show a warning with a count and a link to a remediation guide.

### 10.3 API routes (backend)

```
GET  /api/config/{customer_id}                    # Load current config
PUT  /api/config/{customer_id}                    # Save config (increments version)
GET  /api/config/{customer_id}/versions           # List version history
GET  /api/config/{customer_id}/versions/{v}       # Get specific version
POST /api/config/validate                         # Validate config, return errors + warnings
POST /api/config/preview-scope                    # Count assets matching scope
POST /api/config/simulate                         # Dry-run simulation against live findings
GET  /api/findings/active                         # Dashboard: current in-scope findings
GET  /api/approvals/pending                       # Dashboard: pending approval requests
GET  /api/audit                                   # Paginated audit log
POST /api/approval/{approval_id}/respond          # Approve / reject / defer (from UI)
```

### 10.4 Dashboard page

Beyond the wizard, build a dashboard at `/dashboard` with:

- Summary metric cards: findings in scope, pending approvals, remediations this week, open escalations
- A findings table: severity badge, category, asset name, blast level, age, status (triaging / awaiting approval / scheduled / completed / failed)
- A pending approvals panel with inline approve/defer buttons
- An activity feed: last 20 agent actions with timestamps and reasoning summaries
- A "Dry-run report" section (only visible when dry_run=True): what the agent would have done in the last 7 days

---

## 11. Approval card UX

### 11.1 Google Chat card specification

The card sent to approvers must include, in order:

1. Header: "Remediation approval required" + severity badge (colour-coded)
2. Asset name (full GCP resource path) + short name
3. Finding category + CVE IDs (if OS vuln)
4. One-sentence plan summary
5. Risk assessment paragraph (from plan agent)
6. Blast radius: level (LOW/MEDIUM/HIGH/CRITICAL) + count of prod dependencies
7. Environment: env label + team label + owner
8. Estimated downtime and whether a reboot is required
9. Rollback plan (first 3 steps, truncated with "view full plan" link)
10. Three buttons: **Approve** (green) · **Reject** (red) · **Defer to window** (grey)
11. Footer: approval ID, expiry time, link to full audit entry in the UI

### 11.2 Approval response handling

On button click, the Chat webhook fires to the approval webhook endpoint on Cloud Run. The handler:

- Validates the approver's identity against the configured approvers list
- Records the response with timestamp and approver email
- Updates the Firestore approval document
- Updates the Chat card to reflect the decision (replace buttons with "Approved by X at HH:MM")
- Enqueues the remediation job (if approved) or writes the deferral record (if deferred)
- Sends a confirmation DM to the approver

### 11.3 Escalation flow

If no response is received within `escalate_after_minutes` (default 15 for critical):

1. Send the same card to the fallback approver group
2. Escalate the PagerDuty alert to the next escalation level
3. Add an escalation entry to the audit log
4. If still no response after a second timeout (configurable, default 60 min for critical), create a P1 incident and pause auto-scheduling until a human responds

---

## 12. Agent Garden publication

### 12.1 `agent.yaml` publication fields

```yaml
marketplace:
  icon: assets/icon.png                     # 512x512 PNG
  screenshots:
    - assets/screenshot-dashboard.png
    - assets/screenshot-approval-card.png
    - assets/screenshot-config.png
  long_description: |
    scc-remediation-agent connects to Security Command Center, builds a
    comprehensive asset graph of your GCP organisation, and autonomously
    remediates security findings — with human approval gates, blast radius
    analysis, and full audit trails.

    Customers configure which projects and assets to scope, set severity
    thresholds, define approval chains, and control execution modes. The
    agent handles the rest.
  documentation_url: https://your-docs-site/scc-remediation-agent
  support_url: https://github.com/your-org/scc-remediation-agent/issues
  required_permissions:
    - securitycenter.findings.list
    - cloudasset.assets.listResource
    - osconfig.patchJobs.create
    - iam.roles.list
  deployment_type: customer_project          # runs in customer's own GCP project
```

### 12.2 Onboarding flow

When a customer installs the agent from Agent Garden:

1. Agent Platform provisions the service account with required roles (pre-specified in `agent.yaml`).
2. The agent runs an **onboarding check**: validates API access, counts resources, checks label coverage (owner=, env=, team=).
3. Produces an onboarding report with any gaps (missing labels, missing APIs, unsupported asset types).
4. Customer is directed to the Config UI to complete the 5-step wizard.
5. Config is saved with `dry_run: true` and the agent begins its first ingestion cycle.
6. After 24 hours in dry-run, the agent sends a "shadow mode report" showing what it would have done.
7. Customer explicitly enables execution in the Config UI.

---

## 13. Testing strategy

### 13.1 Unit tests

Write unit tests for all of:

- `config/schema.py` — Pydantic model validation, `matches_asset()`, `to_api_values()`
- `config/validator.py` — error and warning generation
- `scheduler/windows.py` — maintenance window computation across timezones, week boundaries
- `scheduler/freeze.py` — freeze detection logic
- `agent/agents/triage_agent.py` — deduplication, severity filtering, exposure filter
- `agent/agents/impact_agent.py` — blast level classification logic
- `graph/ingestion/finding_ingester.py` — normalisation, field mapping

Use `pytest`. Mock all GCP API calls using `unittest.mock` and the fixtures in `tests/fixtures/`.

### 13.2 Integration tests

- Full ingestion → graph → triage cycle against a test Neo4j instance using `tests/fixtures/mock_assets.json` and `tests/fixtures/mock_findings.json`
- Approval dispatch and response cycle (mock Chat/PagerDuty endpoints)
- Maintenance window scheduling end-to-end (Cloud Tasks emulator)

### 13.3 Fixture data

`tests/fixtures/mock_findings.json` — include at least:
- 2 CRITICAL OS vulnerability findings on prod assets
- 1 HIGH misconfiguration on a prod asset with 5 downstream dependencies
- 1 CRITICAL finding on a dormant dev asset (auto-approve candidate)
- 1 finding on an out-of-scope asset (should be filtered)

`tests/fixtures/mock_assets.json` — include a realistic org hierarchy: 3 projects, mix of GCE instances, GKE clusters, Cloud SQL instances, GCS buckets, with varied label coverage.

---

## 14. Security and IAM requirements

- The agent service account must follow **least privilege** — never grant `roles/owner`, `roles/editor`, or `roles/iam.admin`.
- All API keys and service account credentials are stored in **Secret Manager**. Never in environment variables or source code.
- The Neo4j database is accessible only from within the GKE cluster via internal DNS. No external LoadBalancer.
- The Config UI backend validates every request against **Identity-Aware Proxy** — no unauthenticated access.
- The approval webhook endpoint validates that the responding user's email is in the configured approvers list before processing any action.
- All Terraform changes go through **Cloud Build** with a separate limited-privilege service account — the main agent SA does not have direct Terraform apply permissions.
- Config changes are **append-only** in Firestore — the agent code never deletes config history.
- The BigQuery audit dataset uses **table-level ACLs** — write-only for the agent SA, read-only for security team members.
- All inter-service communication uses **Workload Identity** — no long-lived service account keys.

---

## 15. Open questions and decisions log

| # | Question | Decision | Date |
|---|---|---|---|
| 1 | Neo4j Community vs Spanner Graph | Start with Neo4j Community on GKE for flexibility; evaluate Spanner Graph when customer count exceeds 10 | TBD |
| 2 | Gemini model selection for plan agent | gemini-2.0-pro for planning (higher quality), gemini-2.0-flash for triage/dormancy (speed + cost) | TBD |
| 3 | Multi-tenant vs per-customer deployment | Per-customer deployment in customer's own GCP project — required for data residency and security posture | Decided |
| 4 | IAM tightening execution — direct API vs PR | Default to PR (safer); direct API only if explicitly enabled and blast_level = LOW | TBD |
| 5 | Owner label resolution fallback | If `owner=` label missing, fall back to project-level `owner=` label, then to config default approver | TBD |
| 6 | Config UI auth — IAP vs custom auth | Identity-Aware Proxy using customer's Google Workspace identity | Decided |
| 7 | Maximum findings per cycle | Cap at 100 per cycle to prevent runaway scheduling; excess findings queue to next cycle | TBD |
| 8 | ITSM change ticket integration | Jira in v1; ServiceNow in v2 | TBD |
| 9 | Rollback execution — automated vs manual | Rollback plan always generated; automated rollback execution only for OS patches (safe); manual for IAM/firewall | TBD |
| 10 | Dormancy threshold — 30 days | Configurable per customer; default 30 days with override via config | TBD |

---

## 16. Graph tools implementation (`agent/tools/graph_tools.py`)

This section specifies the complete implementation of `graph_tools.py` — the module
called throughout the agent core. It covers three concerns:

1. How relationships are pulled from the Asset Inventory API and written to Neo4j
2. The Neo4j driver connection wrapper
3. Every function signature called elsewhere in the spec, with its Cypher query

### 16.1 Important: relationship API prerequisite

The Asset Inventory relationship types require **SCC Premium or Enterprise tier**.
This is already assumed by the agent (SCC is the finding source), so no additional
entitlement is needed. The relationship content type is requested via
`contentType=RELATIONSHIP` alongside a `relationshipTypes` list. Do not request
all relationship types in one call — the API will error if any requested type is
unsupported for the given asset types. Use the batched approach in section 16.3.

### 16.2 Neo4j connection wrapper

```python
# agent/tools/graph_tools.py
from neo4j import GraphDatabase, Driver
from functools import lru_cache
import os

NEO4J_URI = os.environ.get("NEO4J_URI", "bolt://neo4j.neo4j.svc.cluster.local:7687")
NEO4J_USER = os.environ.get("NEO4J_USER", "neo4j")
NEO4J_PASSWORD_SECRET = os.environ.get("NEO4J_PASSWORD_SECRET", "neo4j-password")

@lru_cache(maxsize=1)
def _get_driver() -> Driver:
    """
    Returns a cached Neo4j driver. Password is read from Secret Manager at
    first call. The lru_cache means the driver is a process-level singleton —
    appropriate for Cloud Run where each instance handles one request at a time.
    """
    password = _read_secret(NEO4J_PASSWORD_SECRET)
    return GraphDatabase.driver(NEO4J_URI, auth=(NEO4J_USER, password))

def _read_secret(secret_id: str) -> str:
    from google.cloud import secretmanager
    client = secretmanager.SecretManagerServiceClient()
    project_id = os.environ["GOOGLE_CLOUD_PROJECT"]
    name = f"projects/{project_id}/secrets/{secret_id}/versions/latest"
    response = client.access_secret_version(request={"name": name})
    return response.payload.data.decode("UTF-8")

def _run_query(cypher: str, params: dict = None) -> list[dict]:
    """Execute a read query and return list of record dicts."""
    driver = _get_driver()
    with driver.session() as session:
        result = session.run(cypher, params or {})
        return [dict(record) for record in result]

def _run_write(cypher: str, params: dict = None) -> None:
    """Execute a write query (MERGE / SET)."""
    driver = _get_driver()
    with driver.session() as session:
        session.execute_write(lambda tx: tx.run(cypher, params or {}))
```

### 16.3 Relationship ingestion from Asset Inventory API

The Asset Inventory RELATIONSHIP content type returns one record per
source→target→relationship_type triple. The ingester below pulls all
security-relevant relationship types in grouped batches (the API requires
that all requested relationship types are valid for the requested asset types),
then writes edges into Neo4j with MERGE to stay idempotent.

```python
# graph/ingestion/relationship_ingester.py
from google.cloud import asset_v1

# Relationship types grouped by their source asset type.
# Only request types that are valid for the given source asset_types.
# Requires SCC Premium/Enterprise. Full list:
# https://cloud.google.com/asset-inventory/docs/relationship-types
RELATIONSHIP_BATCHES = [
    {
        "label": "compute_instance_relationships",
        "asset_types": ["compute.googleapis.com/Instance"],
        "relationship_types": [
            "COMPUTE_INSTANCE_USE_DISK",           # Instance → Disk
            "INSTANCE_TO_INSTANCEGROUP",           # Instance → MIG/Unmanaged IG
            "COMPUTE_INSTANCE_USE_NETWORK_INTERFACE", # Instance → Network
            "COMPUTE_INSTANCE_USE_SUBNETWORK",     # Instance → Subnetwork
            "COMPUTE_INSTANCE_USE_ADDRESS",        # Instance → Static IP
            "COMPUTE_INSTANCE_USE_BACKEND_SERVICE", # Instance → Backend Service
        ],
    },
    {
        "label": "network_relationships",
        "asset_types": [
            "compute.googleapis.com/Network",
            "compute.googleapis.com/Subnetwork",
            "compute.googleapis.com/Firewall",
            "compute.googleapis.com/ForwardingRule",
            "compute.googleapis.com/BackendService",
        ],
        "relationship_types": [
            "COMPUTE_NETWORK_CONTAIN_SUBNETWORK",  # VPC → Subnet
            "COMPUTE_FIREWALL_APPLY_TO_NETWORK",   # Firewall → VPC
            "COMPUTE_BACKEND_SERVICE_USE_HEALTH_CHECK",
            "COMPUTE_FORWARDING_RULE_USE_BACKEND_SERVICE",
            "COMPUTE_SUBNETWORK_CONTAIN_IP_RANGE",
        ],
    },
    {
        "label": "gke_relationships",
        "asset_types": [
            "container.googleapis.com/Cluster",
            "container.googleapis.com/NodePool",
        ],
        "relationship_types": [
            "GKE_CLUSTER_CONTAIN_NODEPOOL",        # Cluster → NodePool
            "GKE_NODEPOOL_USE_INSTANCE_TEMPLATE",  # NodePool → Instance Template
        ],
    },
    {
        "label": "iam_service_account_relationships",
        "asset_types": [
            "compute.googleapis.com/Instance",
            "container.googleapis.com/Cluster",
            "run.googleapis.com/Service",
            "cloudfunctions.googleapis.com/CloudFunction",
        ],
        "relationship_types": [
            "COMPUTE_INSTANCE_USE_SERVICE_ACCOUNT", # Instance → SA
        ],
    },
    {
        "label": "storage_relationships",
        "asset_types": [
            "storage.googleapis.com/Bucket",
            "bigquery.googleapis.com/Dataset",
            "bigquery.googleapis.com/Table",
            "sqladmin.googleapis.com/Instance",
        ],
        "relationship_types": [
            "BIGQUERY_DATASET_CONTAIN_TABLE",      # Dataset → Table
        ],
    },
]

# Neo4j relationship type mapping:
# API relationship_type string → Neo4j edge label used in the graph
RELATIONSHIP_TYPE_TO_NEO4J = {
    "COMPUTE_INSTANCE_USE_DISK":               "USES_DISK",
    "INSTANCE_TO_INSTANCEGROUP":               "BELONGS_TO_GROUP",
    "COMPUTE_INSTANCE_USE_NETWORK_INTERFACE":  "CONNECTS_TO",
    "COMPUTE_INSTANCE_USE_SUBNETWORK":         "IN_SUBNET",
    "COMPUTE_INSTANCE_USE_ADDRESS":            "USES_ADDRESS",
    "COMPUTE_INSTANCE_USE_BACKEND_SERVICE":    "SERVES_TRAFFIC_VIA",
    "COMPUTE_NETWORK_CONTAIN_SUBNETWORK":      "CONTAINS",
    "COMPUTE_FIREWALL_APPLY_TO_NETWORK":       "APPLIES_TO_NETWORK",
    "COMPUTE_BACKEND_SERVICE_USE_HEALTH_CHECK":"HEALTH_CHECKED_BY",
    "COMPUTE_FORWARDING_RULE_USE_BACKEND_SERVICE": "ROUTES_TRAFFIC_TO",
    "GKE_CLUSTER_CONTAIN_NODEPOOL":            "HOSTED_BY",
    "GKE_NODEPOOL_USE_INSTANCE_TEMPLATE":      "USES_TEMPLATE",
    "COMPUTE_INSTANCE_USE_SERVICE_ACCOUNT":    "USES_SERVICE_ACCOUNT",
    "BIGQUERY_DATASET_CONTAIN_TABLE":          "CONTAINS",
    "COMPUTE_SUBNETWORK_CONTAIN_IP_RANGE":     "CONTAINS",
    "COMPUTE_BACKEND_SERVICE_USE_HEALTH_CHECK":"HEALTH_CHECKED_BY",
}

def ingest_all_relationships(org_id: str) -> dict:
    """
    Pulls all relationship batches from Asset Inventory and writes edges to Neo4j.
    Returns a summary dict: {batch_label: edge_count}.
    """
    summary = {}
    client = asset_v1.AssetServiceClient()

    for batch in RELATIONSHIP_BATCHES:
        edges = _fetch_relationship_batch(
            client=client,
            org_id=org_id,
            asset_types=batch["asset_types"],
            relationship_types=batch["relationship_types"],
        )
        _write_edges_to_neo4j(edges)
        summary[batch["label"]] = len(edges)
        print(f"[relationships] {batch['label']}: {len(edges)} edges written")

    # IAM relationships are sourced separately from IAM_POLICY content type
    iam_edges = _ingest_iam_relationships(client, org_id)
    summary["iam_bindings"] = len(iam_edges)

    return summary

def _fetch_relationship_batch(
    client,
    org_id: str,
    asset_types: list[str],
    relationship_types: list[str],
) -> list[dict]:
    """
    Fetches one batch of relationships. Returns list of
    {source, target, relationship_type, neo4j_label} dicts.
    """
    edges = []
    request = asset_v1.ListAssetsRequest(
        parent=f"organizations/{org_id}",
        asset_types=asset_types,
        content_type=asset_v1.ContentType.RELATIONSHIP,
        relationship_types=relationship_types,
        page_size=500,
    )

    try:
        for asset in client.list_assets(request=request):
            # The API returns one asset record per source resource.
            # asset.related_assets contains the list of related resources.
            if not asset.related_assets:
                continue
            source = asset.name
            for related in asset.related_assets.related_assets:
                rel_type = asset.related_assets.relationship_attributes.relationship_type \
                    if asset.related_assets.relationship_attributes else "UNKNOWN"
                edges.append({
                    "source": source,
                    "target": related.asset,
                    "relationship_type": rel_type,
                    "neo4j_label": RELATIONSHIP_TYPE_TO_NEO4J.get(rel_type, "RELATED_TO"),
                    "source_type": asset.asset_type,
                    "target_type": related.asset_type,
                })
    except Exception as e:
        print(f"[relationships] Warning: batch failed for {asset_types}: {e}")
        # Non-fatal — some relationship types may not be available in all orgs

    return edges

def _write_edges_to_neo4j(edges: list[dict]) -> None:
    """
    Writes relationship edges to Neo4j using MERGE to stay idempotent.
    Uses a dynamic relationship label from neo4j_label.
    Batches writes in groups of 500.
    """
    if not edges:
        return

    # Neo4j doesn't support dynamic relationship types in a single parameterised
    # query, so we group by neo4j_label and issue one MERGE query per label type.
    from collections import defaultdict
    by_label = defaultdict(list)
    for e in edges:
        by_label[e["neo4j_label"]].append(e)

    for label, label_edges in by_label.items():
        # Batch in groups of 500 to avoid large transactions
        for i in range(0, len(label_edges), 500):
            batch = label_edges[i:i+500]
            cypher = f"""
            UNWIND $edges AS e
            MATCH (src:Resource {{asset_name: e.source}})
            MATCH (tgt:Resource {{asset_name: e.target}})
            MERGE (src)-[r:{label}]->(tgt)
            SET r.relationship_type = e.relationship_type,
                r.last_synced = datetime()
            """
            _run_write(cypher, {"edges": batch})

def _ingest_iam_relationships(client, org_id: str) -> list[dict]:
    """
    Pulls IAM_POLICY content type to extract GRANTS_ACCESS_TO edges.
    These are not available via RELATIONSHIP content type — they come
    from the IAM policy bindings on each resource.
    Returns list of edges written.
    """
    from google.cloud import asset_v1

    edges = []
    request = asset_v1.ListAssetsRequest(
        parent=f"organizations/{org_id}",
        asset_types=[
            "compute.googleapis.com/Instance",
            "storage.googleapis.com/Bucket",
            "bigquery.googleapis.com/Dataset",
            "container.googleapis.com/Cluster",
            "cloudresourcemanager.googleapis.com/Project",
        ],
        content_type=asset_v1.ContentType.IAM_POLICY,
        page_size=500,
    )

    for asset in client.list_assets(request=request):
        if not asset.iam_policy:
            continue
        resource_name = asset.name
        for binding in asset.iam_policy.bindings:
            role = binding.role
            for member in binding.members:
                # Only track service account → resource bindings for graph edges
                # (user/group bindings are stored as properties, not edges)
                if member.startswith("serviceAccount:"):
                    sa_email = member.replace("serviceAccount:", "")
                    edges.append({
                        "resource": resource_name,
                        "sa_email": sa_email,
                        "role": role,
                    })

    # Write GRANTS_ACCESS_TO edges
    if edges:
        cypher = """
        UNWIND $edges AS e
        MATCH (r:Resource {asset_name: e.resource})
        MERGE (sa:Resource {asset_name: 'serviceAccount:' + e.sa_email})
          ON CREATE SET sa.asset_type = 'iam.googleapis.com/ServiceAccount',
                        sa.short_name = e.sa_email
        MERGE (sa)-[rel:GRANTS_ACCESS_TO]->(r)
        SET rel.role = e.role,
            rel.last_synced = datetime()
        """
        for i in range(0, len(edges), 500):
            _run_write(cypher, {"edges": edges[i:i+500]})

    return edges
```

### 16.4 Function signatures called by agent code

These are all the functions imported from `graph_tools` elsewhere in the spec.
Each includes its full implementation with the Cypher query it executes.

```python
# --- Scope checking ---

def get_resource_scope_status(asset_name: str, scope_config) -> dict:
    """
    Returns whether the asset is in scope per the customer's config.
    Reads labels and project from the graph (already ingested).
    Called by: triage_agent.py
    """
    rows = _run_query(
        "MATCH (r:Resource {asset_name: $name}) "
        "RETURN r.labels AS labels, r.project AS project, r.in_scope AS in_scope",
        {"name": asset_name}
    )
    if not rows:
        return {"in_scope": False, "reason": "asset_not_in_graph"}

    r = rows[0]
    asset = {"labels": r.get("labels") or {}, "project": r.get("project", "")}
    in_scope = scope_config.matches_asset(asset)
    return {
        "in_scope": in_scope,
        "project": asset["project"],
        "labels": asset["labels"],
    }


# --- Resource metadata ---

def get_resource_metadata(asset_name: str) -> dict:
    """
    Returns full metadata dict for a resource node.
    Called by: impact_agent.py
    """
    rows = _run_query(
        """
        MATCH (r:Resource {asset_name: $name})
        RETURN r.env AS env, r.team AS team, r.owner_email AS owner_email,
               r.data_class AS data_class, r.status AS status,
               r.maint_window AS maint_window, r.labels AS labels,
               r.dormancy_score AS dormancy_score, r.last_activity AS last_activity
        """,
        {"name": asset_name}
    )
    return rows[0] if rows else {}


def get_resource_labels(asset_name: str) -> dict:
    """
    Returns just the labels map for a resource. Used by freeze checker.
    Called by: scheduler/freeze.py
    """
    rows = _run_query(
        "MATCH (r:Resource {asset_name: $name}) RETURN r.labels AS labels",
        {"name": asset_name}
    )
    return rows[0].get("labels") or {} if rows else {}


def get_resource_maint_window(asset_name: str) -> str | None:
    """
    Returns the maint-window label value for a resource, or None if not set.
    Called by: scheduler/windows.py
    """
    rows = _run_query(
        "MATCH (r:Resource {asset_name: $name}) RETURN r.maint_window AS mw",
        {"name": asset_name}
    )
    val = rows[0].get("mw") if rows else None
    return val if val else None


# --- Blast radius traversal ---

def query_blast_radius(asset_name: str, max_hops: int = 3) -> list[dict]:
    """
    Returns all resources reachable from asset_name within max_hops.
    Traverses CONNECTS_TO, ROUTES_TRAFFIC_TO, DEPENDS_ON, GRANTS_ACCESS_TO,
    HOSTED_BY, USES_SERVICE_ACCOUNT, IN_SUBNET edges.
    Called by: impact_agent.py
    """
    rows = _run_query(
        f"""
        MATCH path = (vuln:Resource {{asset_name: $asset_name}})-
          [:CONNECTS_TO|ROUTES_TRAFFIC_TO|DEPENDS_ON|GRANTS_ACCESS_TO|
           HOSTED_BY|USES_SERVICE_ACCOUNT|IN_SUBNET*1..{max_hops}]->
          (downstream:Resource)
        WHERE downstream.asset_name <> $asset_name
        WITH downstream,
             min(length(path)) AS hops,
             collect(DISTINCT [r in relationships(path) | type(r)][0]) AS edge_types
        RETURN downstream.asset_name AS name,
               downstream.env AS env,
               downstream.team AS team,
               downstream.data_class AS data_class,
               downstream.asset_type AS asset_type,
               hops,
               edge_types
        ORDER BY hops ASC, downstream.env DESC
        LIMIT 50
        """,
        {"asset_name": asset_name}
    )
    return rows


# --- IAM lateral movement paths ---

def query_iam_paths(asset_name: str) -> list[dict]:
    """
    Finds service accounts with access to the vulnerable resource that
    also have access to prod resources — lateral movement risk.
    Called by: impact_agent.py
    """
    rows = _run_query(
        """
        MATCH (vuln:Resource {asset_name: $asset_name})
              <-[:GRANTS_ACCESS_TO]-(sa:Resource)
        MATCH (sa)-[:GRANTS_ACCESS_TO]->(prod:Resource {env: 'prod'})
        WHERE prod.asset_name <> $asset_name
        RETURN sa.asset_name AS service_account,
               sa.short_name AS sa_email,
               collect(DISTINCT prod.asset_name)[..10] AS reachable_prod_resources,
               count(DISTINCT prod) AS prod_blast_count
        ORDER BY prod_blast_count DESC
        LIMIT 10
        """,
        {"asset_name": asset_name}
    )
    return rows


# --- Dormancy check ---

def check_dormancy(asset_name: str) -> dict:
    """
    Returns dormancy classification for a resource.
    dormancy_score is populated during ingestion by compute_dormancy_score().
    Called by: dormancy_agent.py
    """
    rows = _run_query(
        """
        MATCH (r:Resource {asset_name: $name})
        RETURN r.dormancy_score AS dormancy_score,
               r.last_activity AS last_activity,
               r.status AS status,
               CASE
                 WHEN r.dormancy_score > 0.8 THEN 'DORMANT'
                 WHEN r.dormancy_score > 0.4 THEN 'PERIODIC'
                 ELSE 'ACTIVE'
               END AS dormancy_class
        """,
        {"name": asset_name}
    )
    if not rows:
        return {"dormancy_class": "ACTIVE", "dormancy_score": 0.0,
                "last_activity": None, "status": "UNKNOWN"}
    return rows[0]


# --- Scope preview (used by config validator) ---

async def count_in_scope_assets(scope_config, org_id: str) -> int:
    """
    Counts assets currently in the graph that match the scope config.
    Used by config/validator.py for the UI preview.
    Note: only accurate after the first asset ingestion run.
    """
    # Pull all resources and filter in Python using scope_config.matches_asset().
    # This is acceptable because the graph is within the same cluster —
    # latency is low. For very large orgs (>100k resources), push
    # the label filter into Cypher instead.
    all_resources = _run_query(
        "MATCH (r:Resource) RETURN r.asset_name AS name, "
        "r.project AS project, r.labels AS labels"
    )
    count = 0
    for r in all_resources:
        asset = {"project": r.get("project", ""), "labels": r.get("labels") or {}}
        if scope_config.matches_asset(asset):
            count += 1
    return count


# --- State updates (called after remediation) ---

def update_resource_finding_state(
    asset_name: str,
    finding_id: str,
    new_state: str,
) -> None:
    """
    Updates the state of a finding node and sets last_patched on the resource.
    Called by: verify_agent.py
    """
    _run_write(
        """
        MATCH (f:Finding {finding_id: $finding_id})-[:AFFECTS]->(r:Resource {asset_name: $asset_name})
        SET f.state = $new_state,
            f.resolved_at = datetime(),
            r.last_patched = datetime()
        """,
        {"finding_id": finding_id, "asset_name": asset_name, "new_state": new_state}
    )


def mark_assets_in_scope(scope_config, org_id: str) -> int:
    """
    Sets in_scope=true/false on all Resource nodes based on current scope config.
    Called during the ingestion cycle after scope config changes.
    Returns count of in-scope assets.
    """
    all_resources = _run_query(
        "MATCH (r:Resource) RETURN r.asset_name AS name, "
        "r.project AS project, r.labels AS labels"
    )
    in_scope_names = []
    out_of_scope_names = []

    for r in all_resources:
        asset = {"project": r.get("project", ""), "labels": r.get("labels") or {}}
        if scope_config.matches_asset(asset):
            in_scope_names.append(r["name"])
        else:
            out_of_scope_names.append(r["name"])

    if in_scope_names:
        _run_write(
            "UNWIND $names AS n MATCH (r:Resource {asset_name: n}) SET r.in_scope = true",
            {"names": in_scope_names}
        )
    if out_of_scope_names:
        _run_write(
            "UNWIND $names AS n MATCH (r:Resource {asset_name: n}) SET r.in_scope = false",
            {"names": out_of_scope_names}
        )

    return len(in_scope_names)


# --- Utility used by asset_ingester ---

def _get_project_resource(asset_name: str) -> str:
    """Returns the project resource name for a given asset. Used by freeze.py."""
    rows = _run_query(
        "MATCH (r:Resource {asset_name: $name})-[:BELONGS_TO]->(p:Project) "
        "RETURN '//cloudresourcemanager.googleapis.com/projects/' + p.project_id AS project_resource",
        {"name": asset_name}
    )
    return rows[0]["project_resource"] if rows else ""
```

### 16.5 Ingestion pipeline: full sequence

The complete ingestion cycle that calls all of the above in the right order:

```python
# graph/ingestion/run_full_sync.py
import asyncio
from graph.ingestion.asset_ingester import export_assets
from graph.ingestion.finding_ingester import list_active_findings
from graph.ingestion.relationship_ingester import ingest_all_relationships
from graph.ingestion.iam_ingester import ingest_iam_bindings
from agent.tools.graph_tools import mark_assets_in_scope
from config.loader import load_config
from dormancy import compute_dormancy_score
import os

async def run_full_sync(customer_id: str):
    config = load_config(customer_id)
    org_id = config.org_id

    print("[sync] Step 1: export all assets → write Resource nodes")
    assets = export_assets(org_id)
    _upsert_resource_nodes(assets, config)

    print("[sync] Step 2: ingest relationships → write edges")
    rel_summary = ingest_all_relationships(org_id)
    print(f"[sync] Relationships: {rel_summary}")

    print("[sync] Step 3: ingest SCC findings → write Finding nodes + AFFECTS edges")
    findings = list(list_active_findings(
        org_id,
        severity_filter=["CRITICAL", "HIGH", "MEDIUM", "LOW"]  # full ingest, no filter
    ))
    _upsert_finding_nodes(findings)

    print("[sync] Step 4: compute dormancy scores")
    _update_dormancy_scores(assets, config)

    print("[sync] Step 5: mark in-scope assets")
    in_scope_count = mark_assets_in_scope(config.scope, org_id)
    print(f"[sync] {in_scope_count} assets marked in scope")

    print("[sync] Full sync complete")

def _upsert_resource_nodes(assets: list[dict], config):
    from agent.tools.graph_tools import _run_write

    for i in range(0, len(assets), 500):
        batch = assets[i:i+500]
        # Derive env/team/owner from labels
        for a in batch:
            labels = a.get("labels") or {}
            a["env"] = labels.get("env", labels.get("environment", "unknown"))
            a["team"] = labels.get("team", "unknown")
            a["owner_email"] = labels.get("owner", "")
            a["data_class"] = labels.get("data-class", labels.get("data_class", ""))
            a["maint_window"] = labels.get("maint-window", "")
            a["in_scope"] = False   # will be set properly in step 5

        _run_write("""
        UNWIND $assets AS a
        MERGE (r:Resource {asset_name: a.asset_name})
        SET r.asset_type   = a.asset_type,
            r.short_name   = split(a.asset_name, '/')[-1],
            r.project      = a.project,
            r.location     = a.location,
            r.env          = a.env,
            r.team         = a.team,
            r.owner_email  = a.owner_email,
            r.data_class   = a.data_class,
            r.maint_window = a.maint_window,
            r.status       = a.status,
            r.labels       = a.labels,
            r.in_scope     = a.in_scope,
            r.last_synced  = datetime()
        """, {"assets": batch})

        # Write BELONGS_TO → Project edges
        _run_write("""
        UNWIND $assets AS a
        MERGE (p:Project {project_id: a.project})
        MERGE (r:Resource {asset_name: a.asset_name})-[:BELONGS_TO]->(p)
        """, {"assets": batch})

def _upsert_finding_nodes(findings: list[dict]):
    from agent.tools.graph_tools import _run_write

    for i in range(0, len(findings), 500):
        batch = findings[i:i+500]
        _run_write("""
        UNWIND $findings AS f
        MERGE (fn:Finding {finding_id: f.finding_id})
        SET fn.full_name             = f.full_name,
            fn.category              = f.category,
            fn.severity              = f.severity,
            fn.finding_class         = f.finding_class,
            fn.cve_ids               = f.cve_ids,
            fn.cvss_score            = f.cvss_score,
            fn.attack_exposure_score = f.attack_exposure_score,
            fn.attack_exposure_state = f.attack_exposure_state,
            fn.remediation_text      = f.remediation_text,
            fn.state                 = 'ACTIVE',
            fn.last_synced           = datetime()
        WITH fn, f
        MATCH (r:Resource {asset_name: f.resource_name})
        MERGE (fn)-[:AFFECTS]->(r)
        """, {"findings": batch})

def _update_dormancy_scores(assets: list[dict], config):
    from agent.tools.graph_tools import _run_write
    project_id = os.environ.get("GOOGLE_CLOUD_PROJECT", "")

    updates = []
    for a in assets:
        if a.get("asset_type") == "compute.googleapis.com/Instance":
            score = compute_dormancy_score(a["asset_name"], a["project"])
            updates.append({"name": a["asset_name"], "score": score})

    if updates:
        _run_write("""
        UNWIND $updates AS u
        MATCH (r:Resource {asset_name: u.name})
        SET r.dormancy_score = u.score
        """, {"updates": updates})
```

### 16.6 Neo4j indexes to create at setup

Run these after the constraints in section 5.1. They are required for the
traversal queries to perform acceptably on large graphs.

```cypher
CREATE INDEX resource_env IF NOT EXISTS FOR (r:Resource) ON (r.env);
CREATE INDEX resource_project IF NOT EXISTS FOR (r:Resource) ON (r.project);
CREATE INDEX resource_in_scope IF NOT EXISTS FOR (r:Resource) ON (r.in_scope);
CREATE INDEX resource_dormancy IF NOT EXISTS FOR (r:Resource) ON (r.dormancy_score);
CREATE INDEX finding_severity IF NOT EXISTS FOR (f:Finding) ON (f.severity);
CREATE INDEX finding_state IF NOT EXISTS FOR (f:Finding) ON (f.state);
CREATE INDEX finding_exposure IF NOT EXISTS FOR (f:Finding) ON (f.attack_exposure_score);
```

---

*End of specification. Last updated: 2026-04-23. Version: 1.1.0.*
*Changes in v1.1: Added section 16 — complete graph_tools implementation, relationship ingestion from Asset Inventory API, full sync pipeline, and Neo4j indexes.*
