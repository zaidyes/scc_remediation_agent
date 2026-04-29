# Local testing against a real GCP org

Two modes — pick based on how much you want to test:

| | Mode A — Interactive chat | Mode B — Full dry-run pipeline |
|-|--------------------------|-------------------------------|
| **Setup time** | ~10 min | ~30 min |
| **Local infra** | None | Neo4j + Firestore emulator (Docker) |
| **What runs** | ADK chat → real SCC/CAI queries | Full cycle: triage → impact → plan |
| **Graph blast radius** | Limited (no Neo4j) | Full (ingested from org) |
| **Executes anything?** | No | No (dry_run=True always) |
| **Best for** | Exploring findings interactively | End-to-end pipeline validation |

---

## Prerequisites

### 1. LLM access — AI Studio (recommended) or Vertex AI

The only reason a GCP project ID is required is for the Gemini API. Everything else (SCC reads, CAI traversal, IAM analysis) is org-scoped — no project needed.

**Option A — AI Studio API key (easiest, free, no GCP project needed):**
```bash
# Get a free key at https://aistudio.google.com/apikey
# Pass it to the script as --api-key YOUR_KEY
```

**Option B — Vertex AI (requires a GCP project with billing):**
```bash
gcloud services enable aiplatform.googleapis.com --project=YOUR_PROJECT
# Pass --project YOUR_PROJECT to the script
```

### 2. GCP permissions (org-level read — no project roles needed for the data)

Grant these at the **org level** on your user account:

| Role | Why |
|------|-----|
| `roles/securitycenter.findingsViewer` | Read SCC findings |
| `roles/cloudasset.viewer` | Read Cloud Asset Inventory (assets, IAM) |
| `roles/iam.securityReviewer` | `analyzeIamPolicy` calls |
| `roles/compute.viewer` | Instance and network metadata |

```bash
ORG_ID=123456789012
USER=$(gcloud config get-value account)

gcloud organizations add-iam-policy-binding $ORG_ID \
  --member="user:$USER" --role="roles/securitycenter.findingsViewer"

gcloud organizations add-iam-policy-binding $ORG_ID \
  --member="user:$USER" --role="roles/cloudasset.viewer"

gcloud organizations add-iam-policy-binding $ORG_ID \
  --member="user:$USER" --role="roles/iam.securityReviewer"

gcloud organizations add-iam-policy-binding $ORG_ID \
  --member="user:$USER" --role="roles/compute.viewer"
```

If you're using Vertex AI (not AI Studio), also grant on the project:
```bash
gcloud projects add-iam-policy-binding YOUR_PROJECT \
  --member="user:$USER" --role="roles/aiplatform.user"
```

### 2. Tools

```bash
# gcloud CLI
gcloud auth application-default login \
  --scopes=https://www.googleapis.com/auth/cloud-platform

# uv (Python package manager)
curl -LsSf https://astral.sh/uv/install.sh | sh

# Docker Desktop (Mode B only)
# https://www.docker.com/products/docker-desktop/
```

---

## Mode A — Interactive chat (no local infra)

```bash
# With AI Studio key (no GCP project needed)
./scripts/local_test.sh \
  --org-id YOUR_ORG_ID \
  --api-key YOUR_AI_STUDIO_KEY \
  --mode A

# Or with Vertex AI
./scripts/local_test.sh \
  --org-id YOUR_ORG_ID \
  --project YOUR_GCP_PROJECT \
  --mode A
```

This starts an ADK chat session (`adk run app`). You can ask the agent things like:

```
> What are the most critical SCC findings in my org right now?
> Tell me about the blast radius of //compute.googleapis.com/projects/my-project/instances/vm1
> What would the remediation plan be for finding find-001?
```

The agent will query your real SCC and CAI APIs. Graph-based blast radius queries will return empty since there's no Neo4j, but triage, pre-flight checks, and plan generation all work.

---

## Mode B — Full dry-run batch pipeline

```bash
# With AI Studio key
./scripts/local_test.sh \
  --org-id YOUR_ORG_ID \
  --api-key YOUR_AI_STUDIO_KEY \
  --mode B \
  --project-ids proj-1,proj-2   # optional: narrow to specific projects
  --severity HIGH_PLUS           # optional: CRITICAL_ONLY | HIGH_PLUS | MEDIUM_PLUS | ALL

# Or with Vertex AI
./scripts/local_test.sh \
  --org-id YOUR_ORG_ID \
  --project YOUR_GCP_PROJECT \
  --mode B
```

The script:
1. Authenticates ADC
2. Installs Python deps
3. Starts Neo4j + Firestore emulator via Docker
4. Seeds a `local-test` customer config in Firestore
5. Runs graph ingestion (pulls assets, IAM, findings from your real org into local Neo4j)
6. Runs the full remediation batch cycle — triage → impact → blast radius → plan

Everything is `dry_run=True`. No GCP resources are modified. No patch jobs, IAM changes, or firewall rules are applied.

### Manual step-by-step (if you prefer not to use the script)

```bash
# 1. Start local infra
docker compose up -d neo4j firestore-emulator

# 2. Copy and edit env
cp .env.local .env
# Fill in: GOOGLE_CLOUD_PROJECT, ORG_ID

# 3. Install deps
uv sync

# 4. Seed config
export FIRESTORE_EMULATOR_HOST=localhost:8080
python scripts/seed_local_config.py --org-id YOUR_ORG_ID --project-ids proj-1,proj-2

# 5. Run ingestion
python graph/ingestion/run_full_sync.py

# 6. Run the agent
python -m app --customer-id local-test

# Or interactively:
scc-agent run --customer-id local-test
```

---

## Scoping to specific projects

If your org is large, narrow the scope to avoid long ingestion times:

```bash
./scripts/local_test.sh \
  --org-id 123456789012 \
  --project my-test-project \
  --project-ids security-prod,platform-prod \
  --severity CRITICAL_ONLY \
  --mode B
```

You can also add `--skip-ingestion` to re-run the agent against an already-ingested graph:

```bash
./scripts/local_test.sh --org-id 123456789 --project my-project --mode B --skip-ingestion
```

---

## Inspecting results

**Neo4j browser** (Mode B): http://localhost:7474 — log in with `neo4j/localpassword`

Useful queries:
```cypher
// What findings did the agent process?
MATCH (f:Finding)-[:AFFECTS]->(r:Resource) RETURN f, r LIMIT 25

// What's the blast radius of a specific asset?
MATCH (r:Resource {asset_name: '//compute.googleapis.com/projects/p/instances/vm1'})
      -[:DEPENDS_ON*1..3]->(downstream)
RETURN r, downstream

// Which assets have CRITICAL findings?
MATCH (f:Finding {severity: 'CRITICAL'})-[:AFFECTS]->(r:Resource)
RETURN r.short_name, r.project, f.category ORDER BY r.project
```

**CLI** (both modes):
```bash
# Show what approvals the dry-run would have generated
scc-agent status --customer-id local-test --format json
```

---

## Troubleshooting

**`PERMISSION_DENIED` on SCC calls**
Verify your ADC account has `securitycenter.findingsViewer` at org level:
```bash
gcloud organizations get-iam-policy YOUR_ORG_ID \
  --flatten="bindings[].members" \
  --filter="bindings.members:$(gcloud config get-value account)"
```

**`PERMISSION_DENIED` on CAI calls**
CAI requires `cloudasset.viewer` at org level (not just project level).

**Neo4j connection refused**
```bash
docker compose ps          # check it's running
docker compose logs neo4j  # check for startup errors
```

**Firestore emulator not detected**
Ensure `FIRESTORE_EMULATOR_HOST=localhost:8080` is exported before running Python:
```bash
export FIRESTORE_EMULATOR_HOST=localhost:8080
python -m app --customer-id local-test
```

**Gemini / Vertex AI errors**
Check `GOOGLE_CLOUD_PROJECT` is set to a project with Vertex AI API enabled:
```bash
gcloud services enable aiplatform.googleapis.com --project=YOUR_PROJECT
```
Or switch to AI Studio (no project billing needed):
```bash
# In .env:
GOOGLE_GENAI_USE_VERTEXAI=False
GOOGLE_API_KEY=your-ai-studio-key
```

**Large org taking too long**
Add `--project-ids` to restrict ingestion scope, or use `--severity CRITICAL_ONLY` to cut down findings.
