#!/usr/bin/env bash
# ─────────────────────────────────────────────────────────────────────────────
# local_test.sh — sets up and runs the SCC Remediation Agent locally against
# a real GCP org (dry-run, no resources are modified).
#
# Usage:
#   ./scripts/local_test.sh --org-id ORG_ID [options]
#
# Options:
#   --org-id          GCP organisation ID (required)
#   --api-key         AI Studio API key — use instead of Vertex AI / project
#                     Get one free at https://aistudio.google.com/apikey
#   --project         GCP project ID — only needed if using Vertex AI (no --api-key)
#   --project-ids     Comma-separated project IDs to scope findings to
#                     (default: all projects in org)
#   --severity        CRITICAL_ONLY | HIGH_PLUS (default) | MEDIUM_PLUS | ALL
#   --customer-id     Config ID to use in Firestore (default: local-test)
#   --mode            A = chat only, B = full batch dry-run (default: A)
#   --skip-infra      Skip docker-compose up (if Neo4j/Firestore already running)
#   --skip-ingestion  Skip graph ingestion step
#
# Prerequisites:
#   - gcloud CLI installed and authenticated (org-level read roles)
#   - Docker Desktop running (for mode B)
#   - uv installed (https://astral.sh/uv)
#
# Required GCP permissions (grant at org level):
#   roles/securitycenter.findingsViewer   — read SCC findings
#   roles/cloudasset.viewer               — read Cloud Asset Inventory
#   roles/iam.securityReviewer            — analyzeIamPolicy calls
#   roles/compute.viewer                  — network/instance metadata
#
# For Vertex AI (if not using --api-key, grant on the project):
#   roles/aiplatform.user
#   roles/datastore.user                  — Firestore (only if not using emulator)
# ─────────────────────────────────────────────────────────────────────────────
set -euo pipefail

# ── Defaults ─────────────────────────────────────────────────────────────────
ORG_ID=""
PROJECT=""
API_KEY=""
PROJECT_IDS=""
SEVERITY="HIGH_PLUS"
CUSTOMER_ID="local-test"
MODE="A"
SKIP_INFRA=false
SKIP_INGESTION=false

# ── Argument parsing ──────────────────────────────────────────────────────────
while [[ $# -gt 0 ]]; do
  case "$1" in
    --org-id)        ORG_ID="$2";        shift 2 ;;
    --project)       PROJECT="$2";       shift 2 ;;
    --api-key)       API_KEY="$2";       shift 2 ;;
    --project-ids)   PROJECT_IDS="$2";   shift 2 ;;
    --severity)      SEVERITY="$2";      shift 2 ;;
    --customer-id)   CUSTOMER_ID="$2";   shift 2 ;;
    --mode)          MODE="$2";          shift 2 ;;
    --skip-infra)    SKIP_INFRA=true;    shift ;;
    --skip-ingestion) SKIP_INGESTION=true; shift ;;
    *) echo "Unknown option: $1"; exit 1 ;;
  esac
done

if [[ -z "$ORG_ID" ]]; then
  echo "Usage: $0 --org-id ORG_ID [--api-key AI_STUDIO_KEY | --project GCP_PROJECT] [options]"
  exit 1
fi

# --api-key and --project are mutually exclusive; one is required for the LLM
if [[ -z "$API_KEY" && -z "$PROJECT" ]]; then
  echo "Error: provide either --api-key (AI Studio, free) or --project (Vertex AI)"
  echo ""
  echo "  AI Studio key (no GCP project needed):"
  echo "    https://aistudio.google.com/apikey"
  echo ""
  echo "  Or a GCP project with Vertex AI enabled:"
  echo "    gcloud services enable aiplatform.googleapis.com --project=YOUR_PROJECT"
  exit 1
fi

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT_DIR="$(dirname "$SCRIPT_DIR")"
cd "$ROOT_DIR"

echo ""
echo "══════════════════════════════════════════════════════"
echo "  SCC Remediation Agent — Local Test Setup"
echo "  Org     : $ORG_ID"
if [[ -n "$API_KEY" ]]; then
echo "  LLM     : AI Studio (no GCP project needed)"
else
echo "  LLM     : Vertex AI (project: $PROJECT)"
fi
echo "  Mode    : $MODE ($([ "$MODE" = "A" ] && echo "interactive chat" || echo "full dry-run batch"))"
echo "══════════════════════════════════════════════════════"
echo ""

# ── Step 1: Check auth ────────────────────────────────────────────────────────
echo "▶ Checking GCP authentication..."
if ! gcloud auth application-default print-access-token &>/dev/null; then
  echo "  No ADC credentials found. Running gcloud auth..."
  gcloud auth application-default login \
    --scopes=https://www.googleapis.com/auth/cloud-platform
fi
echo "  ✓ Authenticated as $(gcloud config get-value account 2>/dev/null)"

# ── Step 2: Install Python dependencies ──────────────────────────────────────
echo ""
echo "▶ Installing Python dependencies..."
uv sync --quiet
echo "  ✓ Dependencies ready"

# ── Step 3: Write .env ───────────────────────────────────────────────────────
echo ""
echo "▶ Writing .env..."
if [[ -n "$API_KEY" ]]; then
  # AI Studio path — no real GCP project needed for the LLM
  cat > .env <<EOF
GOOGLE_GENAI_USE_VERTEXAI=False
GOOGLE_API_KEY=${API_KEY}
GOOGLE_CLOUD_PROJECT=local-test
GOOGLE_CLOUD_LOCATION=us-central1
ORG_ID=${ORG_ID}
CUSTOMER_ID=${CUSTOMER_ID}
MODEL_ID=gemini-3-flash-preview
PLANNING_MODEL_ID=gemini-3.1-pro-preview
NEO4J_URI=bolt://localhost:7687
NEO4J_USERNAME=neo4j
NEO4J_PASSWORD=localpassword
EOF
else
  # Vertex AI path
  cat > .env <<EOF
GOOGLE_GENAI_USE_VERTEXAI=True
GOOGLE_CLOUD_PROJECT=${PROJECT}
GOOGLE_CLOUD_LOCATION=us-central1
ORG_ID=${ORG_ID}
CUSTOMER_ID=${CUSTOMER_ID}
MODEL_ID=gemini-3-flash-preview
PLANNING_MODEL_ID=gemini-3.1-pro-preview
NEO4J_URI=bolt://localhost:7687
NEO4J_USERNAME=neo4j
NEO4J_PASSWORD=localpassword
EOF
fi

if [[ "$MODE" == "B" ]]; then
  echo "FIRESTORE_EMULATOR_HOST=localhost:8080" >> .env
fi
echo "  ✓ .env written"

# ─────────────────────────────────────────────────────────────────────────────
# MODE A: Interactive chat only (no local infra needed)
# ─────────────────────────────────────────────────────────────────────────────
if [[ "$MODE" == "A" ]]; then
  echo ""
  echo "══════════════════════════════════════════════════════"
  echo "  Mode A — Interactive ADK chat"
  echo "  The agent will query your real SCC findings and"
  echo "  CAI data. No local database is needed."
  echo "  Graph-based blast radius will be limited — ask the"
  echo "  agent about specific findings by resource name."
  echo "══════════════════════════════════════════════════════"
  echo ""
  echo "Starting interactive session... (Ctrl+C to exit)"
  echo ""
  source .env
  export GOOGLE_CLOUD_PROJECT GOOGLE_GENAI_USE_VERTEXAI GOOGLE_CLOUD_LOCATION
  export MODEL_ID PLANNING_MODEL_ID NEO4J_URI NEO4J_USERNAME NEO4J_PASSWORD
  uv run adk run app
  exit 0
fi

# ─────────────────────────────────────────────────────────────────────────────
# MODE B: Full dry-run batch pipeline
# ─────────────────────────────────────────────────────────────────────────────

# ── Step 4: Start local infra ─────────────────────────────────────────────────
if [[ "$SKIP_INFRA" == "false" ]]; then
  echo ""
  echo "▶ Starting Neo4j + Firestore emulator..."
  docker compose up -d neo4j firestore-emulator

  echo "  Waiting for Neo4j to be ready..."
  until docker compose exec -T neo4j cypher-shell -u neo4j -p localpassword "RETURN 1" &>/dev/null; do
    sleep 2
    echo -n "."
  done
  echo ""
  echo "  ✓ Neo4j ready  (browser: http://localhost:7474)"

  echo "  Waiting for Firestore emulator..."
  until curl -sf http://localhost:8080 &>/dev/null; do
    sleep 2
    echo -n "."
  done
  echo ""
  echo "  ✓ Firestore emulator ready"
fi

# ── Step 5: Seed customer config ──────────────────────────────────────────────
echo ""
echo "▶ Writing customer config to Firestore..."
source .env
export FIRESTORE_EMULATOR_HOST GOOGLE_CLOUD_PROJECT CUSTOMER_ID
SEED_ARGS="--org-id $ORG_ID --customer-id $CUSTOMER_ID --severity $SEVERITY"
if [[ -n "$PROJECT_IDS" ]]; then
  SEED_ARGS="$SEED_ARGS --project-ids $PROJECT_IDS"
fi
uv run python scripts/seed_local_config.py $SEED_ARGS

# ── Step 6: Graph ingestion ───────────────────────────────────────────────────
if [[ "$SKIP_INGESTION" == "false" ]]; then
  echo ""
  echo "▶ Running graph ingestion (assets + IAM + findings from org $ORG_ID)..."
  echo "  This may take a few minutes for large orgs."
  export NEO4J_URI NEO4J_USERNAME NEO4J_PASSWORD
  uv run python -c "
import asyncio, os, sys
sys.path.insert(0, '.')
os.environ.setdefault('ORG_ID', '$ORG_ID')
from graph.ingestion.run_full_sync import run_full_sync
asyncio.run(run_full_sync('$CUSTOMER_ID'))
"
  echo "  ✓ Graph ingestion complete"
fi

# ── Step 7: Run the agent ─────────────────────────────────────────────────────
echo ""
echo "══════════════════════════════════════════════════════"
echo "  Mode B — Dry-run batch pipeline"
echo "  dry_run=True: plans generated, nothing executed."
echo "  All output logged to stdout."
echo "══════════════════════════════════════════════════════"
echo ""
uv run python -m app --customer-id "$CUSTOMER_ID"
