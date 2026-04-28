"""
scc-agent CLI — terminal interface for the SCC Remediation Agent.

Two operation modes:
  Local  (default) — calls GCP APIs and Firestore directly via ADC credentials
  Remote (--api-url) — routes mutating commands to a deployed scheduler service

Usage:
  python cli.py <command> [options]
  scc-agent <command> [options]          # after pip install -e .

Commands:
  run       Run the full remediation batch cycle for a customer
  chat      Start an interactive ADK terminal session (local only)
  status    Show pending approvals and recent findings
  approve   Approve a pending remediation request
  reject    Reject a pending remediation request
  rollback  Roll back an executed remediation (24 h window)
  finding   Show details of a specific SCC finding

Global options:
  --customer-id   Customer ID (env: CUSTOMER_ID)
  --api-url       Base URL of deployed scheduler service (enables remote mode)
  --org-id        GCP org ID for finding lookups (env: ORG_ID)
  --format        Output: table (default) | json
"""
import argparse
import asyncio
import datetime
import json
import os
import sys
import textwrap
import urllib.request
import urllib.error


# ---------------------------------------------------------------------------
# Output helpers
# ---------------------------------------------------------------------------

_RESET  = "\033[0m"
_BOLD   = "\033[1m"
_GREEN  = "\033[32m"
_YELLOW = "\033[33m"
_RED    = "\033[31m"
_CYAN   = "\033[36m"
_GREY   = "\033[90m"


def _supports_color() -> bool:
    return sys.stdout.isatty() and os.environ.get("NO_COLOR") is None


def _c(text: str, code: str) -> str:
    return f"{code}{text}{_RESET}" if _supports_color() else text


def _status_color(status: str) -> str:
    colors = {
        "PENDING":     _YELLOW,
        "APPROVED":    _GREEN,
        "REJECTED":    _RED,
        "BLOCKED":     _RED,
        "DEFERRED":    _CYAN,
        "INVALIDATED": _GREY,
        "ACTIVE":      _RED,
        "INACTIVE":    _GREEN,
    }
    return _c(status, colors.get(status, _RESET))


def _blast_color(level: str) -> str:
    colors = {"LOW": _GREEN, "MEDIUM": _YELLOW, "HIGH": _RED, "CRITICAL": _RED}
    return _c(level, colors.get(level, _RESET))


def _print_table(rows: list[dict], columns: list[tuple[str, str]]) -> None:
    """
    Prints a simple aligned table.
    columns: list of (header, dict_key) tuples.
    """
    col_headers = [h for h, _ in columns]
    col_keys    = [k for _, k in columns]

    widths = [len(h) for h in col_headers]
    for row in rows:
        for i, key in enumerate(col_keys):
            widths[i] = max(widths[i], len(str(row.get(key, ""))))

    sep   = "  "
    fmt   = sep.join(f"{{:<{w}}}" for w in widths)
    print(_c(fmt.format(*col_headers), _BOLD))
    print(_c("-" * (sum(widths) + len(sep) * (len(widths) - 1)), _GREY))

    for row in rows:
        vals = []
        for key in col_keys:
            val = str(row.get(key, ""))
            if key == "status":
                val = _status_color(val)
            elif key in ("blast_level", "blast"):
                val = _blast_color(val)
            vals.append(val)
        # Can't use fmt.format with colour codes (changes string length)
        parts = []
        for i, v in enumerate(vals):
            raw = str(rows[rows.index(row) if rows.index(row) >= 0 else 0].get(col_keys[i], ""))
            pad = widths[i] - len(raw)
            parts.append(v + " " * pad)
        print(sep.join(parts))


# ---------------------------------------------------------------------------
# HTTP helper (remote mode)
# ---------------------------------------------------------------------------

def _http(method: str, url: str, payload: dict | None = None, token: str | None = None) -> dict:
    """Minimal HTTP client using stdlib only."""
    data = json.dumps(payload).encode() if payload else None
    req = urllib.request.Request(url, data=data, method=method)
    req.add_header("Content-Type", "application/json")
    if token:
        req.add_header("Authorization", f"Bearer {token}")

    try:
        with urllib.request.urlopen(req, timeout=30) as resp:
            return json.loads(resp.read().decode())
    except urllib.error.HTTPError as e:
        body = e.read().decode()
        try:
            detail = json.loads(body).get("detail", body)
        except Exception:
            detail = body
        print(f"Error {e.code}: {detail}", file=sys.stderr)
        sys.exit(1)
    except urllib.error.URLError as e:
        print(f"Connection error: {e.reason}", file=sys.stderr)
        sys.exit(1)


def _get_id_token(api_url: str) -> str | None:
    """Fetches a GCP OIDC identity token for the target audience via the metadata server."""
    try:
        meta_url = (
            "http://metadata.google.internal/computeMetadata/v1/instance/service-accounts"
            f"/default/identity?audience={api_url}"
        )
        req = urllib.request.Request(meta_url)
        req.add_header("Metadata-Flavor", "Google")
        with urllib.request.urlopen(req, timeout=5) as resp:
            return resp.read().decode()
    except Exception:
        return None


# ---------------------------------------------------------------------------
# Local Firestore helpers
# ---------------------------------------------------------------------------

def _firestore_client():
    try:
        from google.cloud import firestore
        return firestore.Client()
    except ImportError:
        print("google-cloud-firestore is not installed.", file=sys.stderr)
        sys.exit(1)


def _get_approvals_local(customer_id: str, status_filter: str | None = None, limit: int = 20) -> list[dict]:
    db = _firestore_client()
    query = (
        db.collection("approvals")
        .where("customer_id", "==", customer_id)
        .order_by("created_at", direction="DESCENDING")
        .limit(limit)
    )
    if status_filter:
        query = db.collection("approvals") \
            .where("customer_id", "==", customer_id) \
            .where("status", "==", status_filter) \
            .order_by("created_at", direction="DESCENDING") \
            .limit(limit)

    return [doc.to_dict() | {"approval_id": doc.id} for doc in query.stream()]


def _get_findings_local(customer_id: str, limit: int = 10) -> list[dict]:
    db = _firestore_client()
    docs = (
        db.collection("audit_log")
        .where("customer_id", "==", customer_id)
        .where("event_type", "==", "FINDING_STARTED")
        .order_by("timestamp", direction="DESCENDING")
        .limit(limit)
        .stream()
    )
    return [doc.to_dict() for doc in docs]


def _update_approval_local(approval_id: str, customer_id: str, action: str, actor: str) -> dict:
    db = _firestore_client()
    ref = db.collection("approvals").document(approval_id)
    doc = ref.get()
    if not doc.exists:
        print(f"Approval {approval_id} not found.", file=sys.stderr)
        sys.exit(1)
    data = doc.to_dict()
    if data.get("status") != "PENDING":
        print(f"Approval is already {data.get('status')} — cannot {action}.", file=sys.stderr)
        sys.exit(1)

    status_map = {"approve": "APPROVED", "reject": "REJECTED"}
    ref.update({
        "status": status_map[action],
        "responded_by": actor,
        "responded_at": datetime.datetime.utcnow(),
    })

    if action == "approve":
        # Enqueue execution via Cloud Tasks (same path as webhook)
        try:
            from scheduler.main import _enqueue_execution
            from config.schema import CustomerConfig
            config_doc = db.collection("configs").document(customer_id).get()
            if config_doc.exists:
                config = CustomerConfig(**config_doc.to_dict())
                _enqueue_execution(approval_id, data.get("plan", {}), config)
        except Exception as e:
            print(f"Warning: failed to enqueue execution: {e}", file=sys.stderr)

    return {"status": status_map[action], "approval_id": approval_id}


def _rollback_local(approval_id: str) -> dict:
    try:
        from app.tools.rollback_tools import execute_rollback
        return asyncio.run(execute_rollback(approval_id))
    except ImportError as e:
        print(f"Import error: {e}", file=sys.stderr)
        sys.exit(1)


def _get_finding_local(finding_id: str, org_id: str) -> dict | None:
    try:
        from app.tools.scc_tools import get_finding_detail
        return get_finding_detail(finding_id, org_id)
    except ImportError as e:
        print(f"Import error: {e}", file=sys.stderr)
        sys.exit(1)


# ---------------------------------------------------------------------------
# Commands
# ---------------------------------------------------------------------------

def cmd_run(args):
    """Runs the full remediation batch cycle for a customer."""
    customer_id = args.customer_id or os.environ.get("CUSTOMER_ID")
    if not customer_id:
        print("Error: --customer-id is required (or set CUSTOMER_ID).", file=sys.stderr)
        sys.exit(1)

    if args.api_url:
        token = _get_id_token(args.api_url)
        result = _http("POST", f"{args.api_url}/internal/run-cycle",
                       {"customer_id": customer_id}, token)
        print(json.dumps(result, indent=2))
        return

    # Local: direct Python call
    try:
        from google.cloud import firestore
        from config.schema import CustomerConfig
        from app.main import run_remediation_cycle
    except ImportError as e:
        print(f"Import error: {e}", file=sys.stderr)
        sys.exit(1)

    db = firestore.Client()
    doc = db.collection("customer_configs").document(customer_id).get()
    if not doc.exists:
        print(f"No config found for customer_id={customer_id}.", file=sys.stderr)
        sys.exit(1)

    config = CustomerConfig(**doc.to_dict())
    print(f"Starting remediation cycle for {customer_id}...")
    asyncio.run(run_remediation_cycle(config))


def cmd_chat(args):
    """Starts an interactive ADK terminal session."""
    if args.api_url:
        print("chat command is local-only (launches the ADK CLI).", file=sys.stderr)
        sys.exit(1)
    import subprocess
    # adk run app launches root_agent in interactive terminal mode
    result = subprocess.run(["adk", "run", "app"], cwd=os.path.dirname(__file__))
    sys.exit(result.returncode)


def cmd_status(args):
    """Shows pending approvals and recent findings."""
    customer_id = args.customer_id or os.environ.get("CUSTOMER_ID")
    if not customer_id:
        print("Error: --customer-id is required.", file=sys.stderr)
        sys.exit(1)

    status_filter = args.filter  # e.g. PENDING, APPROVED, etc.

    if args.api_url:
        token = _get_id_token(args.api_url)
        params = f"?status={status_filter}" if status_filter else ""
        approvals = _http("GET", f"{args.api_url}/api/approvals/{customer_id}{params}", token=token)
    else:
        approvals = _get_approvals_local(customer_id, status_filter)

    if not approvals:
        print("No approvals found.")
        return

    if args.format == "json":
        print(json.dumps(approvals, indent=2, default=str))
        return

    rows = [
        {
            "approval_id": a.get("approval_id", "")[:12] + "…",
            "finding_id":  a.get("finding_id", "")[:12] + "…",
            "status":      a.get("status", ""),
            "blast":       a.get("blast_level", ""),
            "tier":        str(a.get("tier", "")),
            "asset":       (a.get("asset_name", "") or "").split("/")[-1][:30],
            "created":     str(a.get("created_at", ""))[:16],
        }
        for a in approvals
    ]
    _print_table(rows, [
        ("APPROVAL ID",  "approval_id"),
        ("FINDING ID",   "finding_id"),
        ("STATUS",       "status"),
        ("BLAST",        "blast"),
        ("TIER",         "tier"),
        ("ASSET",        "asset"),
        ("CREATED",      "created"),
    ])
    print(f"\n{len(approvals)} approval(s) shown.")


def cmd_approve(args):
    """Approves a pending remediation request."""
    approval_id = args.approval_id
    customer_id = args.customer_id or os.environ.get("CUSTOMER_ID", "")
    actor = args.actor or os.environ.get("USER", "cli-user")

    if args.api_url:
        token = _get_id_token(args.api_url)
        result = _http("POST", f"{args.api_url}/api/approvals/{approval_id}/approve",
                       {"actor": actor}, token)
    else:
        result = _update_approval_local(approval_id, customer_id, "approve", actor)

    if args.format == "json":
        print(json.dumps(result, indent=2, default=str))
    else:
        print(_c(f"✓ Approved {approval_id}", _GREEN))
        print(f"  Status : {result.get('status')}")
        print(f"  Actor  : {actor}")


def cmd_reject(args):
    """Rejects a pending remediation request."""
    approval_id = args.approval_id
    customer_id = args.customer_id or os.environ.get("CUSTOMER_ID", "")
    actor = args.actor or os.environ.get("USER", "cli-user")

    if args.api_url:
        token = _get_id_token(args.api_url)
        result = _http("POST", f"{args.api_url}/api/approvals/{approval_id}/reject",
                       {"actor": actor}, token)
    else:
        result = _update_approval_local(approval_id, customer_id, "reject", actor)

    if args.format == "json":
        print(json.dumps(result, indent=2, default=str))
    else:
        print(_c(f"✗ Rejected {approval_id}", _RED))
        print(f"  Status : {result.get('status')}")
        print(f"  Actor  : {actor}")


def cmd_rollback(args):
    """Rolls back an executed remediation (within 24 h of execution)."""
    approval_id = args.approval_id

    if not args.yes:
        confirm = input(f"Roll back remediation {approval_id}? This will undo the changes. [y/N] ")
        if confirm.strip().lower() not in ("y", "yes"):
            print("Aborted.")
            return

    if args.api_url:
        token = _get_id_token(args.api_url)
        result = _http("POST", f"{args.api_url}/api/rollback/{approval_id}", token=token)
    else:
        result = _rollback_local(approval_id)

    if args.format == "json":
        print(json.dumps(result, indent=2, default=str))
    else:
        status = result.get("status", "")
        if status == "SUCCESS":
            print(_c(f"✓ Rollback succeeded for {approval_id}", _GREEN))
        else:
            print(_c(f"✗ Rollback failed: {result.get('output', '')}", _RED))
        if result.get("steps_reversed"):
            print(f"  Steps reversed: {result['steps_reversed']}")


def cmd_finding(args):
    """Shows details of a specific SCC finding."""
    finding_id = args.finding_id
    org_id = args.org_id or os.environ.get("ORG_ID", "")

    if args.api_url:
        token = _get_id_token(args.api_url)
        finding = _http("GET", f"{args.api_url}/api/findings/{finding_id}", token=token)
    else:
        if not org_id:
            print("Error: --org-id is required for local finding lookup (or set ORG_ID).", file=sys.stderr)
            sys.exit(1)
        finding = _get_finding_local(finding_id, org_id)
        if not finding:
            print(f"Finding {finding_id} not found.", file=sys.stderr)
            sys.exit(1)

    if args.format == "json":
        print(json.dumps(finding, indent=2, default=str))
        return

    print(_c(f"Finding: {finding_id}", _BOLD))
    print(f"  Resource : {finding.get('resource_name', '')}")
    print(f"  Category : {finding.get('category', '')}")
    severity = finding.get("severity", "")
    print(f"  Severity : {_blast_color(severity)}")
    state = finding.get("state", finding.get("status", ""))
    print(f"  State    : {_status_color(state)}")
    if finding.get("cve_ids"):
        print(f"  CVEs     : {', '.join(finding['cve_ids'])}")
    if finding.get("attack_exposure_score") is not None:
        print(f"  Attack exposure score: {finding['attack_exposure_score']}")
    if finding.get("remediation_text"):
        guidance = textwrap.shorten(finding["remediation_text"], width=80, placeholder="…")
        print(f"  Guidance : {guidance}")


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------

def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="scc-agent",
        description="CLI for the SCC Remediation Agent",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=textwrap.dedent("""\
            Local mode  (default): connects directly to GCP via Application Default Credentials.
            Remote mode (--api-url): routes calls to a deployed scheduler Cloud Run service.

            Examples:
              # Interactive terminal session (ADK chat)
              scc-agent chat

              # Run the batch remediation cycle
              scc-agent run --customer-id acme-prod

              # Show pending approvals
              scc-agent status --customer-id acme-prod --filter PENDING

              # Approve a pending remediation
              scc-agent approve apv-abc123 --customer-id acme-prod

              # Reject a pending remediation
              scc-agent reject apv-abc123 --customer-id acme-prod

              # Roll back an executed remediation
              scc-agent rollback apv-abc123

              # Show finding details
              scc-agent finding find-001 --org-id 123456789

              # All of the above against a remote deployment
              scc-agent status --api-url https://scheduler-abc.run.app --customer-id acme-prod
        """),
    )

    # Global options
    parser.add_argument("--customer-id", help="Customer ID (env: CUSTOMER_ID)")
    parser.add_argument("--org-id", help="GCP org ID for finding lookups (env: ORG_ID)")
    parser.add_argument(
        "--api-url",
        help="Deployed scheduler service base URL — enables remote mode",
    )
    parser.add_argument(
        "--format",
        choices=["table", "json"],
        default="table",
        help="Output format (default: table)",
    )

    sub = parser.add_subparsers(dest="command", metavar="command")
    sub.required = True

    # run
    sub.add_parser("run", help="Run the full remediation batch cycle")

    # chat
    sub.add_parser("chat", help="Start interactive ADK terminal session (local only)")

    # status
    status_p = sub.add_parser("status", help="Show approvals and recent activity")
    status_p.add_argument(
        "--filter",
        metavar="STATUS",
        help="Filter by status: PENDING, APPROVED, REJECTED, BLOCKED, DEFERRED",
    )
    status_p.add_argument("--limit", type=int, default=20, help="Max rows to show (default: 20)")

    # approve
    approve_p = sub.add_parser("approve", help="Approve a pending remediation")
    approve_p.add_argument("approval_id", help="Approval ID to approve")
    approve_p.add_argument("--actor", help="Approver identity (default: $USER)")

    # reject
    reject_p = sub.add_parser("reject", help="Reject a pending remediation")
    reject_p.add_argument("approval_id", help="Approval ID to reject")
    reject_p.add_argument("--actor", help="Rejecter identity (default: $USER)")

    # rollback
    rollback_p = sub.add_parser("rollback", help="Roll back an executed remediation (24 h window)")
    rollback_p.add_argument("approval_id", help="Approval ID to roll back")
    rollback_p.add_argument("-y", "--yes", action="store_true", help="Skip confirmation prompt")

    # finding
    finding_p = sub.add_parser("finding", help="Show SCC finding details")
    finding_p.add_argument("finding_id", help="Finding ID")

    return parser


def main():
    parser = _build_parser()
    args = parser.parse_args()

    dispatch = {
        "run":      cmd_run,
        "chat":     cmd_chat,
        "status":   cmd_status,
        "approve":  cmd_approve,
        "reject":   cmd_reject,
        "rollback": cmd_rollback,
        "finding":  cmd_finding,
    }
    dispatch[args.command](args)


if __name__ == "__main__":
    main()
