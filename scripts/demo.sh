#!/usr/bin/env bash
# =============================================================================
# demo.sh — Provision and run the SCC Remediation Agent demo environment.
#
# Usage:
#   ./scripts/demo.sh [--org-id ORG_ID] [--billing-account BILLING_ACCOUNT]
#
# Flags:
#   --org-id          GCP Organization ID (numeric). Prompted if not provided.
#   --billing-account Billing account ID (XXXXXX-XXXXXX-XXXXXX). Prompted if not provided.
#   --neo4j-password  Neo4j password. Prompted if not provided.
#   --teardown        Destroy the demo environment instead of creating it.
#   --skip-wait       Skip the SCC finding detection wait (use if findings already exist).
# =============================================================================
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/.." && pwd)"
DEMO_TF_DIR="${REPO_ROOT}/terraform/demo"

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

log()    { echo -e "${GREEN}[demo]${NC} $*"; }
warn()   { echo -e "${YELLOW}[warn]${NC}  $*"; }
error()  { echo -e "${RED}[error]${NC} $*" >&2; }
header() { echo -e "\n${BLUE}===${NC} $* ${BLUE}===${NC}"; }

ORG_ID=""
BILLING_ACCOUNT=""
NEO4J_PASSWORD=""
TEARDOWN=false
SKIP_WAIT=false

# --------------------------------------------------------------------------- #
# Parse flags
# --------------------------------------------------------------------------- #
while [[ $# -gt 0 ]]; do
  case "$1" in
    --org-id)           ORG_ID="$2";           shift 2 ;;
    --billing-account)  BILLING_ACCOUNT="$2";  shift 2 ;;
    --neo4j-password)   NEO4J_PASSWORD="$2";   shift 2 ;;
    --teardown)         TEARDOWN=true;          shift   ;;
    --skip-wait)        SKIP_WAIT=true;         shift   ;;
    *) error "Unknown flag: $1"; exit 1 ;;
  esac
done

# --------------------------------------------------------------------------- #
# Prerequisites
# --------------------------------------------------------------------------- #
header "Checking prerequisites"

for cmd in gcloud terraform uv; do
  if ! command -v "$cmd" &>/dev/null; then
    error "Required tool not found: ${cmd}"
    case "$cmd" in
      gcloud)    echo "  Install: https://cloud.google.com/sdk/docs/install" ;;
      terraform) echo "  Install: https://developer.hashicorp.com/terraform/downloads" ;;
      uv)        echo "  Install: curl -LsSf https://astral.sh/uv/install.sh | sh" ;;
    esac
    exit 1
  fi
  log "  ✓ ${cmd} $(${cmd} --version 2>&1 | head -1)"
done

# Verify gcloud is authenticated
if ! gcloud auth print-access-token &>/dev/null; then
  error "Not authenticated with gcloud. Run: gcloud auth login"
  exit 1
fi
log "  ✓ gcloud authenticated as $(gcloud config get-value account 2>/dev/null)"

# --------------------------------------------------------------------------- #
# Collect and validate org ID
# --------------------------------------------------------------------------- #
header "Organization ID"

if [[ -z "$ORG_ID" ]]; then
  echo ""
  echo "The agent requires Organization-level access to Security Command Center."
  echo "Your available organizations:"
  echo ""
  gcloud organizations list --format="table(displayName, name, lifecycleState)" 2>/dev/null || true
  echo ""
  read -rp "Enter your GCP Organization ID (numeric, e.g. 123456789012): " ORG_ID
fi

# Validate: must be numeric
if ! [[ "$ORG_ID" =~ ^[0-9]+$ ]]; then
  error "Organization ID must be numeric. Got: '${ORG_ID}'"
  exit 1
fi

# Validate: caller must have resourcemanager.organizations.get
log "Validating access to organization ${ORG_ID}…"
if ! gcloud organizations describe "$ORG_ID" --format="value(displayName)" &>/dev/null; then
  error "Cannot access organization ${ORG_ID}."
  echo "  Ensure your account has roles/resourcemanager.organizationViewer on the org."
  exit 1
fi

ORG_DISPLAY=$(gcloud organizations describe "$ORG_ID" --format="value(displayName)")
log "  ✓ Organization: ${ORG_DISPLAY} (${ORG_ID})"

# --------------------------------------------------------------------------- #
# Collect billing account
# --------------------------------------------------------------------------- #
header "Billing Account"

if [[ -z "$BILLING_ACCOUNT" ]]; then
  echo ""
  echo "Your available billing accounts:"
  gcloud billing accounts list --format="table(name.segment(1), displayName, open)" 2>/dev/null || true
  echo ""
  read -rp "Enter Billing Account ID (XXXXXX-XXXXXX-XXXXXX): " BILLING_ACCOUNT
fi

if ! [[ "$BILLING_ACCOUNT" =~ ^[A-Z0-9]{6}-[A-Z0-9]{6}-[A-Z0-9]{6}$ ]]; then
  error "Billing account must be in the format XXXXXX-XXXXXX-XXXXXX. Got: '${BILLING_ACCOUNT}'"
  exit 1
fi
log "  ✓ Billing account: ${BILLING_ACCOUNT}"

# --------------------------------------------------------------------------- #
# Collect Neo4j password
# --------------------------------------------------------------------------- #
if [[ -z "$NEO4J_PASSWORD" ]]; then
  echo ""
  read -rsp "Enter a password for the Neo4j demo instance: " NEO4J_PASSWORD
  echo ""
  if [[ ${#NEO4J_PASSWORD} -lt 8 ]]; then
    error "Neo4j password must be at least 8 characters."
    exit 1
  fi
fi

# --------------------------------------------------------------------------- #
# Teardown path
# --------------------------------------------------------------------------- #
if [[ "$TEARDOWN" == true ]]; then
  header "Tearing down demo environment"
  warn "This will delete all three demo projects and the demo folder."
  read -rp "Type 'yes' to confirm teardown: " CONFIRM
  if [[ "$CONFIRM" != "yes" ]]; then
    log "Teardown cancelled."
    exit 0
  fi

  cd "$DEMO_TF_DIR"
  terraform destroy \
    -var="org_id=${ORG_ID}" \
    -var="billing_account=${BILLING_ACCOUNT}" \
    -var="neo4j_password=${NEO4J_PASSWORD}" \
    -auto-approve
  log "Demo environment destroyed."
  exit 0
fi

# --------------------------------------------------------------------------- #
# Terraform apply
# --------------------------------------------------------------------------- #
header "Provisioning demo infrastructure"
log "Working directory: ${DEMO_TF_DIR}"

cd "$DEMO_TF_DIR"

terraform init -upgrade

terraform plan \
  -var="org_id=${ORG_ID}" \
  -var="billing_account=${BILLING_ACCOUNT}" \
  -var="neo4j_password=${NEO4J_PASSWORD}" \
  -out=demo.tfplan

echo ""
read -rp "Apply this plan? (yes/no): " APPLY_CONFIRM
if [[ "$APPLY_CONFIRM" != "yes" ]]; then
  log "Aborted."
  exit 0
fi

terraform apply demo.tfplan

# --------------------------------------------------------------------------- #
# Capture outputs
# --------------------------------------------------------------------------- #
header "Reading Terraform outputs"

INFRA_PROJECT=$(terraform output -raw infra_project_id)
WEB_PROJECT=$(terraform output -raw web_project_id)
DATA_PROJECT=$(terraform output -raw data_project_id)
AGENT_SA=$(terraform output -raw agent_sa_email)
DEMO_FOLDER=$(terraform output -raw demo_folder_id)
NEO4J_INTERNAL_IP=$(terraform output -raw neo4j_internal_ip)
NEO4J_INSTANCE=$(terraform output -raw neo4j_instance_name)
NEO4J_ZONE=$(terraform output -raw neo4j_zone)

log "  infra project : ${INFRA_PROJECT}"
log "  web project   : ${WEB_PROJECT}"
log "  data project  : ${DATA_PROJECT}"
log "  agent SA      : ${AGENT_SA}"
log "  demo folder   : ${DEMO_FOLDER}"
log "  neo4j VM      : ${NEO4J_INSTANCE} (${NEO4J_INTERNAL_IP})"

# --------------------------------------------------------------------------- #
# Wait for Neo4j startup script to complete
# --------------------------------------------------------------------------- #
header "Waiting for Neo4j to start"
log "Neo4j is being installed via startup script on ${NEO4J_INSTANCE}…"
log "(This takes ~3 minutes on first boot)"

NEO4J_READY=false
for i in $(seq 1 20); do
  sleep 15
  STARTUP_DONE=$(gcloud compute ssh "${NEO4J_INSTANCE}" \
    --project="${INFRA_PROJECT}" \
    --zone="${NEO4J_ZONE}" \
    --tunnel-through-iap \
    --command="test -f /var/log/neo4j-startup-done && echo yes || echo no" \
    --quiet 2>/dev/null || echo "no")

  if [[ "$STARTUP_DONE" == "yes" ]]; then
    NEO4J_READY=true
    log "  ✓ Neo4j startup complete (${i} × 15s)"
    break
  fi
  log "  ${i} × 15s — waiting for startup script…"
done

if [[ "$NEO4J_READY" == false ]]; then
  warn "Neo4j startup script did not complete within 5 minutes."
  warn "Check startup logs: gcloud compute ssh ${NEO4J_INSTANCE} --project=${INFRA_PROJECT} --zone=${NEO4J_ZONE} --tunnel-through-iap --command='sudo journalctl -u google-startup-scripts -n 50'"
  warn "Continuing anyway — the agent will retry the connection."
fi

# Open an IAP tunnel in the background so the agent can reach Neo4j locally
log "Opening IAP tunnel: localhost:7687 → ${NEO4J_INSTANCE}:7687"
gcloud compute start-iap-tunnel "${NEO4J_INSTANCE}" 7687 \
  --local-host-port=localhost:7687 \
  --project="${INFRA_PROJECT}" \
  --zone="${NEO4J_ZONE}" \
  --quiet &
IAP_PID=$!
sleep 3  # give the tunnel a moment to establish
log "  ✓ IAP tunnel open (PID ${IAP_PID})"

# Write .env for local development
ENV_FILE="${REPO_ROOT}/.env"
cat > "$ENV_FILE" <<EOF
GOOGLE_CLOUD_PROJECT=${INFRA_PROJECT}
GOOGLE_CLOUD_LOCATION=us-central1
GOOGLE_GENAI_USE_VERTEXAI=True
MODEL_ID=gemini-3-flash-preview
PLANNING_MODEL_ID=gemini-3.1-pro-preview
NEO4J_URI=bolt://localhost:7687
NEO4J_USERNAME=neo4j
NEO4J_PASSWORD=${NEO4J_PASSWORD}
CLOUD_TASKS_QUEUE=scc-remediation-tasks
CLOUD_TASKS_LOCATION=us-central1
EOF
log "  ✓ Wrote ${ENV_FILE}"

# --------------------------------------------------------------------------- #
# Wait for SCC to detect misconfigurations
# --------------------------------------------------------------------------- #
if [[ "$SKIP_WAIT" == false ]]; then
  header "Waiting for SCC findings"
  echo ""
  warn "SCC typically surfaces misconfiguration findings within 5–15 minutes."
  warn "Vulnerability findings (CVEs) can take up to 24 hours."
  echo ""

  WAIT_MINUTES=10
  log "Waiting ${WAIT_MINUTES} minutes for initial findings…"
  for i in $(seq 1 $WAIT_MINUTES); do
    sleep 60
    FINDING_COUNT=$(gcloud scc findings list "organizations/${ORG_ID}" \
      --filter="state=ACTIVE AND resource.project_display_name~demo" \
      --format="value(name)" 2>/dev/null | wc -l | tr -d ' ')
    log "  ${i}m — active demo findings detected: ${FINDING_COUNT}"
    if [[ "$FINDING_COUNT" -ge 3 ]]; then
      log "  ✓ Enough findings detected, proceeding."
      break
    fi
  done

  if [[ "$FINDING_COUNT" -eq 0 ]]; then
    warn "No findings detected yet. SCC may need more time."
    warn "Re-run with --skip-wait once findings appear, or check the SCC console."
  fi
fi

# --------------------------------------------------------------------------- #
# Install Python dependencies
# --------------------------------------------------------------------------- #
header "Installing Python dependencies"
cd "$REPO_ROOT"
uv sync
log "  ✓ Dependencies installed"

# --------------------------------------------------------------------------- #
# Run the agent in dry-run mode
# --------------------------------------------------------------------------- #
header "Starting agent (dry-run mode)"
echo ""
log "The agent will triage and plan remediations but not execute any changes."
log "Check the Firestore console to see approval requests being created."
echo ""

# Use the infra project as the customer ID for the demo
export GOOGLE_CLOUD_PROJECT="$INFRA_PROJECT"
export GOOGLE_GENAI_USE_VERTEXAI="True"
export NEO4J_PASSWORD="$NEO4J_PASSWORD"

# Seed a minimal dry-run config into Firestore so the agent has something to load
python3 - <<PYTHON
import asyncio
from google.cloud import firestore

async def seed_config():
    db = firestore.AsyncClient(project="${INFRA_PROJECT}")
    config = {
        "customer_id": "${INFRA_PROJECT}",
        "dry_run": True,
        "scope": {
            "folder_ids": ["${DEMO_FOLDER}"],
            "project_ids": [],
            "include_labels": [],
            "exclude_labels": [],
        },
        "severity_threshold": "HIGH_PLUS",
        "filters": {
            "require_active_exposure_path": False,
            "exclude_dormant_assets": True,
            "deduplicate_across_scanners": True,
            "exclude_accepted_risks": True,
        },
        "approval_policy": {
            "tiers": [],
            "approvers": [],
            "auto_approve_enabled": True,
            "notification_channels": [],
            "default_maintenance_window": {
                "days_of_week": [0,1,2,3,4],
                "start_time_utc": "00:00",
                "end_time_utc": "23:59",
                "timezone": "UTC",
            },
        },
        "execution": {
            "enabled_modes": ["MISCONFIGURATION", "FIREWALL", "IAM"],
            "max_blast_radius_for_auto": 5,
        },
        "notifications": {"email_digest_recipients": []},
    }
    await db.collection("customer_configs").document("${INFRA_PROJECT}").set(config)
    print("  ✓ Demo config seeded into Firestore")

asyncio.run(seed_config())
PYTHON

log "Running agent pipeline…"
uv run python -m app.main --customer-id "$INFRA_PROJECT" || true

# --------------------------------------------------------------------------- #
# Launch the UI
# --------------------------------------------------------------------------- #
header "Launching UI"
cd "${REPO_ROOT}/ui"

if ! command -v node &>/dev/null; then
  warn "Node.js not found — skipping UI launch."
  warn "Install Node 18+ and run: cd ui && npm install && npm run dev"
else
  npm install --silent
  log "Starting UI at http://localhost:5173 …"
  log "Starting API backend at http://localhost:8080 …"
  echo ""

  # Start the API backend in the background
  cd "$REPO_ROOT"
  uv run uvicorn ui.api.main:app --port 8080 &
  API_PID=$!

  # Open the browser (macOS)
  sleep 2
  if command -v open &>/dev/null; then
    open "http://localhost:5173"
  fi

  # Start Vite (foreground — Ctrl+C to stop everything)
  cd "${REPO_ROOT}/ui"
  VITE_API_BASE=http://localhost:8080 npm run dev

  # Cleanup on exit
  kill "$API_PID" 2>/dev/null || true
  kill "$IAP_PID" 2>/dev/null || true
fi

# --------------------------------------------------------------------------- #
# Summary
# --------------------------------------------------------------------------- #
header "Demo environment ready"
echo ""
echo "  Org ID          : ${ORG_ID}"
echo "  Org name        : ${ORG_DISPLAY}"
echo "  Infra project   : ${INFRA_PROJECT}"
echo "  Web project     : ${WEB_PROJECT}"
echo "  Data project    : ${DATA_PROJECT}"
echo "  Agent SA        : ${AGENT_SA}"
echo "  Demo folder     : ${DEMO_FOLDER}"
echo ""
echo "  To tear down:   ./scripts/demo.sh --org-id ${ORG_ID} --billing-account ${BILLING_ACCOUNT} --teardown"
echo "  SCC console:    https://console.cloud.google.com/security/command-center/findings?organizationId=${ORG_ID}"
echo ""
