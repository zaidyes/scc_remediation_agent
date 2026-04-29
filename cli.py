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
import itertools
import json
import os
import re
import shutil
import sys
import textwrap
import threading
import time
import urllib.request
import urllib.error


# ---------------------------------------------------------------------------
# Terminal / colour helpers
# ---------------------------------------------------------------------------

_RESET  = "\033[0m"
_BOLD   = "\033[1m"
_DIM    = "\033[2m"
_GREEN  = "\033[32m"
_YELLOW = "\033[33m"
_RED    = "\033[31m"
_CYAN   = "\033[36m"
_BLUE   = "\033[34m"
_GREY   = "\033[90m"
_WHITE  = "\033[97m"


def _supports_color() -> bool:
    return sys.stdout.isatty() and os.environ.get("NO_COLOR") is None


def _c(text: str, *codes: str) -> str:
    if not _supports_color():
        return text
    return "".join(codes) + text + _RESET


def _term_width() -> int:
    return shutil.get_terminal_size((80, 24)).columns


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
        "STABLE":      _GREEN,
        "SUCCESS":     _GREEN,
        "FAILED":      _RED,
    }
    return _c(status, colors.get(status, _RESET))


def _severity_badge(sev: str) -> str:
    badges = {
        "CRITICAL": (_RED,    "● CRITICAL"),
        "HIGH":     (_YELLOW, "● HIGH"),
        "MEDIUM":   (_CYAN,   "● MEDIUM"),
        "LOW":      (_GREY,   "● LOW"),
    }
    code, label = badges.get(sev.upper(), (_GREY, f"● {sev}"))
    return _c(label, _BOLD, code)


def _blast_badge(level: str) -> str:
    badges = {
        "CRITICAL": (_RED,    "▲▲ CRITICAL"),
        "HIGH":     (_RED,    "▲▲ HIGH"),
        "MEDIUM":   (_YELLOW, "▲  MEDIUM"),
        "LOW":      (_GREEN,  "▽  LOW"),
    }
    code, label = badges.get(level.upper(), (_GREY, level))
    return _c(label, code)


# ---------------------------------------------------------------------------
# Spinner
# ---------------------------------------------------------------------------

class _Spinner:
    """Displays an animated spinner on a background thread while work is done."""
    _FRAMES = "⠋⠙⠹⠸⠼⠴⠦⠧⠇⠏"

    def __init__(self, message: str):
        self.message = message
        self._stop = threading.Event()
        self._thread = threading.Thread(target=self._run, daemon=True)

    def _run(self):
        for frame in itertools.cycle(self._FRAMES):
            if self._stop.is_set():
                break
            sys.stdout.write(f"\r{_c(frame, _CYAN)}  {self.message}   ")
            sys.stdout.flush()
            time.sleep(0.08)
        # Clear the spinner line
        sys.stdout.write("\r" + " " * (_term_width() - 1) + "\r")
        sys.stdout.flush()

    def update(self, message: str) -> None:
        self.message = message

    def __enter__(self):
        if _supports_color():
            self._thread.start()
        else:
            print(f"  {self.message}...")
        return self

    def __exit__(self, *_):
        self._stop.set()
        if self._thread.is_alive():
            self._thread.join(timeout=1)


# ---------------------------------------------------------------------------
# Layout helpers
# ---------------------------------------------------------------------------

def _panel(title: str, rows: list[tuple[str, str]], width: int | None = None) -> None:
    """
    Renders a box-drawn panel:
      ╭─ Title ──────────────────╮
      │  Key       value         │
      ╰──────────────────────────╯
    """
    w = min(width or 64, _term_width() - 2)
    key_w = max((len(k) for k, _ in rows), default=8)
    inner = w - 2  # excluding the two │ chars

    top = "╭─ " + title + " " + "─" * max(0, inner - len(title) - 3) + "╮"
    bot = "╰" + "─" * inner + "╯"

    print(_c(top, _GREY))
    for key, val in rows:
        label = _c(key.ljust(key_w), _DIM)
        # Truncate long values to fit the panel
        max_val = inner - key_w - 4
        val_display = str(val)
        if len(val_display) > max_val:
            val_display = val_display[:max_val - 1] + "…"
        print(f"│  {label}  {val_display}")
    print(_c(bot, _GREY))


def _divider(label: str = "") -> None:
    w = _term_width()
    if label:
        pad = (w - len(label) - 2) // 2
        print(_c("─" * pad + " " + label + " " + "─" * pad, _GREY))
    else:
        print(_c("─" * w, _GREY))


def _step(n: int, total: int, msg: str) -> None:
    """Prints a stage progress indicator: [2/4] Running triage..."""
    counter = _c(f"[{n}/{total}]", _GREY)
    print(f"  {counter}  {msg}")


def _ok(msg: str) -> None:
    print(_c("  ✓  ", _GREEN) + msg)


def _err(msg: str) -> None:
    print(_c("  ✗  ", _RED) + msg, file=sys.stderr)


def _warn(msg: str) -> None:
    print(_c("  ⚠  ", _YELLOW) + msg)


def _hint(msg: str) -> None:
    print(_c(f"  {msg}", _GREY))


def _header(subtitle: str = "") -> None:
    """Prints the tool banner."""
    name = _c("scc-agent", _BOLD, _WHITE)
    tag  = _c(f"  {subtitle}", _GREY) if subtitle else ""
    print(f"\n  {name}{tag}\n")


# ---------------------------------------------------------------------------
# Table
# ---------------------------------------------------------------------------

def _print_table(rows: list[dict], columns: list[tuple[str, str]]) -> None:
    """Prints an aligned table with coloured status/blast columns."""
    col_headers = [h for h, _ in columns]
    col_keys    = [k for _, k in columns]

    widths = [len(h) for h in col_headers]
    for row in rows:
        for i, key in enumerate(col_keys):
            widths[i] = max(widths[i], len(str(row.get(key, ""))))

    sep = "  "
    print("  " + _c(sep.join(h.ljust(widths[i]) for i, h in enumerate(col_headers)), _BOLD))
    print("  " + _c(sep.join("─" * w for w in widths), _GREY))

    for row in rows:
        parts = []
        for i, key in enumerate(col_keys):
            raw = str(row.get(key, ""))
            pad = widths[i] - len(raw)
            if key == "status":
                cell = _status_color(raw)
            elif key in ("blast_level", "blast"):
                cell = _blast_badge(raw) if raw else ""
                pad  = widths[i] - len(raw)  # colour codes don't count
            elif key == "severity":
                cell = _severity_badge(raw) if raw else ""
                pad  = widths[i] - len(raw)
            else:
                cell = raw
            parts.append(cell + " " * pad)
        print("  " + sep.join(parts))


# ---------------------------------------------------------------------------
# HTTP helper (remote mode)
# ---------------------------------------------------------------------------

def _http(method: str, url: str, payload: dict | None = None, token: str | None = None) -> dict:
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
        _err(f"HTTP {e.code}: {detail}")
        sys.exit(1)
    except urllib.error.URLError as e:
        _err(f"Connection error: {e.reason}")
        sys.exit(1)


def _get_id_token(api_url: str) -> str | None:
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
        _err("google-cloud-firestore is not installed.")
        sys.exit(1)


def _get_approvals_local(customer_id: str, status_filter: str | None = None, limit: int = 20) -> list[dict]:
    db = _firestore_client()
    q = (
        db.collection("approvals")
        .where("customer_id", "==", customer_id)
        .order_by("created_at", direction="DESCENDING")
        .limit(limit)
    )
    if status_filter:
        q = (
            db.collection("approvals")
            .where("customer_id", "==", customer_id)
            .where("status", "==", status_filter)
            .order_by("created_at", direction="DESCENDING")
            .limit(limit)
        )
    return [doc.to_dict() | {"approval_id": doc.id} for doc in q.stream()]


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
        _err(f"Approval {approval_id} not found.")
        sys.exit(1)
    data = doc.to_dict()
    if data.get("status") != "PENDING":
        _err(f"Approval is already {data.get('status')} — cannot {action}.")
        sys.exit(1)

    status_map = {"approve": "APPROVED", "reject": "REJECTED"}
    ref.update({
        "status": status_map[action],
        "responded_by": actor,
        "responded_at": datetime.datetime.utcnow(),
    })

    if action == "approve":
        try:
            from scheduler.main import _enqueue_execution
            from config.schema import CustomerConfig
            config_doc = db.collection("configs").document(customer_id).get()
            if config_doc.exists:
                config = CustomerConfig(**config_doc.to_dict())
                _enqueue_execution(approval_id, data.get("plan", {}), config)
        except Exception as e:
            _warn(f"Failed to enqueue execution: {e}")

    return {"status": status_map[action], "approval_id": approval_id, "_data": data}


def _rollback_local(approval_id: str) -> dict:
    try:
        from app.tools.rollback_tools import execute_rollback
        return asyncio.run(execute_rollback(approval_id))
    except ImportError as e:
        _err(f"Import error: {e}")
        sys.exit(1)


def _get_finding_local(finding_id: str, org_id: str) -> dict | None:
    try:
        from app.tools.scc_tools import get_finding_detail
        return get_finding_detail(finding_id, org_id)
    except ImportError as e:
        _err(f"Import error: {e}")
        sys.exit(1)


# ---------------------------------------------------------------------------
# Commands
# ---------------------------------------------------------------------------

def cmd_run(args):
    customer_id = args.customer_id or os.environ.get("CUSTOMER_ID")
    if not customer_id:
        _err("--customer-id is required (or set CUSTOMER_ID).")
        sys.exit(1)

    _header(f"run  ·  {customer_id}")

    if args.api_url:
        with _Spinner("Triggering remote run cycle..."):
            token = _get_id_token(args.api_url)
            result = _http("POST", f"{args.api_url}/internal/run-cycle",
                           {"customer_id": customer_id}, token)
        print(json.dumps(result, indent=2))
        return

    try:
        from google.cloud import firestore
        from config.schema import CustomerConfig
        from app.main import run_remediation_cycle
    except ImportError as e:
        _err(f"Import error: {e}")
        sys.exit(1)

    _step(1, 4, "Loading customer config...")
    db = firestore.Client()
    doc = db.collection("customer_configs").document(customer_id).get()
    if not doc.exists:
        _err(f"No config found for customer_id={customer_id}.")
        sys.exit(1)
    config = CustomerConfig(**doc.to_dict())

    _step(2, 4, "Fetching active findings...")
    _step(3, 4, "Running remediation pipeline...")
    with _Spinner("Agent is working — this may take a few minutes"):
        asyncio.run(run_remediation_cycle(config))

    _step(4, 4, "Done.")
    print()
    _ok(f"Remediation cycle complete for {customer_id}")
    _hint("Run  scc-agent status --customer-id " + customer_id + "  to see results.")
    print()


# ---------------------------------------------------------------------------
# Models command
# ---------------------------------------------------------------------------

def cmd_models(args):
    """Lists available Gemini models and optionally selects new defaults."""
    import sys as _sys
    _sys.path.insert(0, os.path.dirname(__file__))
    from scripts.discover_models import (
        discover_models, print_model_table,
        select_models_interactive, write_env_models,
    )

    _header("models")

    print(_c("  Querying available Gemini models...", _GREY), end=" ", flush=True)
    try:
        models = discover_models()
        print(_c("done", _GREEN))
    except Exception as exc:
        print(_c(f"failed", _RED))
        _err(str(exc))
        sys.exit(1)

    current_flash = os.environ.get("MODEL_ID", "")
    current_pro   = os.environ.get("PLANNING_MODEL_ID", "")
    print_model_table(models, current_flash, current_pro)

    # Show current config
    print(f"  {'Current flash':16}  {_c(current_flash or '(not set)', _YELLOW if not current_flash else _CYAN)}")
    print(f"  {'Current pro':16}  {_c(current_pro   or '(not set)', _YELLOW if not current_pro   else _CYAN)}")
    print()

    if getattr(args, "select", False):
        selected = select_models_interactive(models)
        flash = selected.get("flash", models["flash"][0] if models["flash"] else "")
        pro   = selected.get("pro",   models["pro"][0]   if models["pro"] else "")

        if not flash and not pro:
            _err("No models selected.")
            sys.exit(1)

        env_path = os.path.join(os.path.dirname(__file__) or ".", ".env")
        write_env_models(flash, pro, env_path)
        print()
        _ok(f"Written to {env_path}")
        print(f"  {'MODEL_ID':20}  {flash}")
        print(f"  {'PLANNING_MODEL_ID':20}  {pro}")
        print()
        _hint("Run  source .env  or re-run local_test.sh to apply.")
        print()
    else:
        flash_latest = models["flash"][0] if models["flash"] else ""
        pro_latest   = models["pro"][0]   if models["pro"] else ""
        _hint("Run  scc-agent models --select  to pick and save new defaults.")
        if flash_latest and flash_latest != current_flash:
            _hint(f"Newer flash listed: {flash_latest}  (run --select to test access)")
        if pro_latest and pro_latest != current_pro:
            _hint(f"Newer pro listed: {pro_latest}  (run --select to test access)")
        print()


# ---------------------------------------------------------------------------
# Interactive chat REPL (replaces `adk run app`)
# ---------------------------------------------------------------------------

_SLASH_HELP = """\
  /help           show this message
  /model          list available models and switch the active model
  /status         show pending approvals (uses --customer-id from session)
  /finding <id>   show details for a finding ID
  /clear          clear the screen
  /exit           end the session (also Ctrl+C)
"""


def _print_session_summary(
    turns: int,
    total_tokens: int,
    prompt_tokens: int,
    output_tokens: int,
    start_time: float,
    model_id: str,
) -> None:
    elapsed = int(time.time() - start_time)
    dur = f"{elapsed // 60}m{elapsed % 60:02d}s" if elapsed >= 60 else f"{elapsed}s"
    print()
    print(_c("  Session summary", _BOLD))
    _divider()
    rows = [
        ("Model",    model_id),
        ("Turns",    str(turns)),
        ("Tokens",   f"{total_tokens:,}  (in: {prompt_tokens:,}  out: {output_tokens:,})"),
        ("Duration", dur),
    ]
    key_w = max(len(k) for k, _ in rows)
    for k, v in rows:
        print(f"  {_c(k.ljust(key_w), _DIM)}  {v}")
    print()


def _stats_line(turn: int, total_tokens: int, elapsed_secs: int, model_id: str) -> str:
    dur = f"{elapsed_secs // 60}m{elapsed_secs % 60:02d}s" if elapsed_secs >= 60 else f"{elapsed_secs}s"
    return _c(
        f"  {model_id}  ·  turn {turn}  ·  {total_tokens:,} tok  ·  {dur}",
        _GREY,
    )


async def _run_agent_turn(
    runner,
    session,
    user_text: str,
    spinner_msg: str = "Thinking...",
) -> tuple[str, int, int]:
    """
    Sends `user_text` to the agent and collects the final response.
    Returns (response_text, prompt_token_count, output_token_count).
    """
    from google.genai import types as genai_types

    content = genai_types.Content(
        role="user",
        parts=[genai_types.Part(text=user_text)],
    )

    response_parts: list[str] = []
    prompt_tok = 0
    output_tok = 0
    # Human-readable labels for each tool call shown in the spinner
    _TOOL_LABELS: dict[str, str] = {
        "list_active_findings":      "Fetching active findings from SCC...",
        "get_finding_detail":        "Looking up finding details...",
        "mute_resolved_finding":     "Muting resolved finding...",
        "query_blast_radius":        "Analysing blast radius...",
        "query_iam_paths":           "Checking IAM privilege paths...",
        "check_dormancy":            "Checking asset activity...",
        "query_dependency_chain":    "Mapping resource dependencies...",
        "get_network_exposure":      "Assessing network exposure...",
        "validate_plan":             "Validating remediation plan...",
        "dispatch_approval_request": "Sending approval request...",
        "create_patch_job":          "Scheduling patch job...",
    }

    tool_names_seen: set[str] = set()

    try:
        with _Spinner(spinner_msg) as sp:
            async for event in runner.run_async(
                user_id="cli",
                session_id=session.id,
                new_message=content,
            ):
                # Update spinner with a human-readable label for the tool being called
                for fc in (event.get_function_calls() or []):
                    if fc.name not in tool_names_seen:
                        tool_names_seen.add(fc.name)
                        label = _TOOL_LABELS.get(fc.name, f"Running {fc.name}...")
                        sp.update(label)

                # Collect final text from any agent.
                # Sub-agent JSON (triage_agent_output etc.) is translated to a
                # brief stage indicator by _translate_pipeline_json() before display.
                if event.is_final_response() and event.content:
                    for part in event.content.parts:
                        if part.text:
                            response_parts.append(part.text)

                # Collect token usage (last event wins)
                if event.usage_metadata:
                    prompt_tok  = event.usage_metadata.prompt_token_count      or 0
                    output_tok  = event.usage_metadata.candidates_token_count  or 0

    except ValueError as exc:
        # ADK raises ValueError when the model hallucinates a tool name that
        # isn't registered. Surface it as a recoverable error rather than crashing.
        err_msg = str(exc)
        if "not found" in err_msg and "Available tools" in err_msg:
            # Extract the hallucinated name for a cleaner message
            import re as _re
            m = _re.search(r"Tool '([^']+)' not found", err_msg)
            tool_name = m.group(1) if m else "unknown"
            response_parts.append(
                f"I tried to call a tool called `{tool_name}` which doesn't exist. "
                "Please rephrase your request and I'll try a different approach."
            )
        else:
            raise

    return "".join(response_parts).strip(), prompt_tok, output_tok


_URL_RE = re.compile(r"https?://[^\s\)\]\"'>]+")

# Internal output keys written by sub-agents — never shown raw to users
_PIPELINE_KEYS = {
    "triage_agent_output": ("Triage",   lambda d: _fmt_triage(d)),
    "impact_agent_output": ("Impact",   lambda d: _fmt_impact(d)),
    "plan_agent_output":   ("Plan",     lambda d: _fmt_plan(d)),
    "verify_agent_output": ("Verify",   lambda d: _fmt_verify(d)),
}


def _fmt_triage(d: dict) -> str:
    sev     = d.get("severity", "")
    dormant = d.get("is_dormant")
    score   = d.get("attack_exposure_score")
    rat     = d.get("rationale", "")
    in_scope = d.get("in_scope")

    meta = []
    if sev:
        meta.append(f"Severity: {sev}")
    if in_scope is not None:
        meta.append("in scope" if in_scope else "out of scope")
    if dormant is not None:
        meta.append("asset dormant" if dormant else "asset active")
    if score is not None:
        meta.append(f"exposure {score}")

    lines = [f"## Triage  —  {'  ·  '.join(meta) if meta else 'complete'}"]
    if rat:
        lines += ["", rat]
    return "\n".join(lines)


def _fmt_impact(d: dict) -> str:
    level   = d.get("blast_level", "")
    assets  = d.get("blast_radius_assets", [])
    count   = d.get("blast_radius_count") or len(assets)
    exposed = d.get("internet_exposed")
    iam     = d.get("iam_paths", [])

    meta = []
    if level:
        meta.append(f"Blast radius: {level}")
    if count:
        meta.append(f"{count} downstream resource{'s' if count != 1 else ''}")
    if exposed:
        meta.append("internet-exposed")

    lines = [f"## Impact  —  {'  ·  '.join(meta) if meta else 'complete'}"]

    if assets:
        lines += ["", "## Affected resources"]
        for a in assets[:8]:
            name = a.get("asset_name", str(a)).split("/")[-1]
            env  = a.get("env", "")
            lines.append(f"  · {name}" + (f"  ({env})" if env else ""))
        if len(assets) > 8:
            lines.append(f"  … and {len(assets) - 8} more")

    if iam:
        lines += ["", "## IAM privilege paths"]
        for path in iam[:3]:
            lines.append(f"  · {path}")

    return "\n".join(lines)


def _fmt_plan(d: dict) -> str:
    status    = d.get("status", "")
    blocked   = d.get("block_reason", "")

    if status == "BLOCKED":
        lines = ["## Remediation Plan  —  BLOCKED", "", f"  {blocked}"]
        return "\n".join(lines)

    confidence   = d.get("confidence", "")
    downtime     = d.get("estimated_downtime_minutes")
    reboot       = d.get("requires_reboot", False)
    change_win   = d.get("change_window_required", False)
    summary      = d.get("summary", "")
    risk         = d.get("risk_assessment", "")
    steps        = d.get("steps", [])
    rollback     = d.get("rollback_steps", [])

    meta = []
    if confidence:
        meta.append(f"Confidence: {confidence}")
    if downtime is not None:
        meta.append(f"~{downtime} min downtime")
    if reboot:
        meta.append("reboot required")
    if change_win:
        meta.append("change window required")

    lines = [f"## Remediation Plan  —  {' · '.join(meta)}"]

    if summary:
        lines += ["", "## Summary", summary]

    if risk:
        lines += ["", "## Risk assessment", risk]

    if steps:
        lines += ["", "## Steps"]
        for s in steps:
            order  = s.get("order", "")
            action = s.get("action", "")
            cmd    = s.get("api_call", "")
            verify = s.get("verification", "")
            lines.append(f"  {order}. {action}")
            if cmd:
                lines.append(f"     {cmd}")
            if verify:
                lines.append(f"     Verify: {verify}")

    if rollback:
        lines += ["", "## Rollback"]
        for s in rollback:
            order  = s.get("order", "")
            action = s.get("action", "")
            cmd    = s.get("api_call", "")
            lines.append(f"  {order}. {action}")
            if cmd:
                lines.append(f"     {cmd}")

    return "\n".join(lines)


def _fmt_verify(d: dict) -> str:
    status = d.get("status", "")
    return status if status else "complete"


def _translate_pipeline_json(text: str) -> str:
    """
    If `text` is (or contains) a JSON block with a known pipeline output key,
    replace it with a concise human-readable stage indicator.
    Otherwise return text unchanged.
    """
    import json

    # Strip markdown code fences if present
    stripped = text.strip()
    if stripped.startswith("```"):
        stripped = re.sub(r"^```[a-z]*\n?", "", stripped)
        stripped = re.sub(r"\n?```$", "", stripped)
        stripped = stripped.strip()

    try:
        obj = json.loads(stripped)
    except (ValueError, TypeError):
        return text  # not JSON — return as-is

    for key, (stage_name, formatter) in _PIPELINE_KEYS.items():
        if key in obj:
            detail = formatter(obj[key])
            # If the formatter used ## sections, return as-is (## renderer handles styling)
            if "\n" in detail or detail.startswith("##"):
                return detail
            # Plain one-liner — prefix with ✓ Stage indicator
            icon  = _c("✓", _GREEN, _BOLD)
            label = _c(stage_name, _BOLD)
            return f"{icon} {label}  {_c(detail, _GREY)}"

    return text  # JSON but not a known pipeline key


def _linkify(text: str) -> str:
    """Wrap URLs in OSC 8 terminal hyperlinks (supported by iTerm2, VSCode, etc.)."""
    if not sys.stdout.isatty() or os.environ.get("NO_COLOR"):
        return text

    def _replace(m: re.Match) -> str:
        url = m.group(0).rstrip(".,;:")  # strip trailing punctuation
        return f"\033]8;;{url}\033\\{url}\033]8;;\033\\"

    return _URL_RE.sub(_replace, text)


def _print_agent_response(text: str) -> None:
    if not text:
        return
    text = _translate_pipeline_json(text)
    tw = max(_term_width() - 6, 40)
    print()
    print(_c("  Agent  ›", _GREY))
    print()
    seen: set[str] = set()
    for line in text.split("\n"):
        stripped = line.strip()
        if stripped:
            # Deduplicate repeated lines (model sometimes echoes menu twice)
            if stripped in seen:
                continue
            seen.add(stripped)
            # Render markdown section headers (## / ###) as bold coloured labels
            if stripped.startswith("### "):
                label = stripped[4:].strip()
                print()
                print("    " + _c(label.upper(), _BOLD, _GREY))
                continue
            if stripped.startswith("## "):
                label = stripped[3:].strip()
                print()
                print("    " + _c(label, _BOLD, _CYAN))
                continue
            # Never wrap lines that contain a URL — wrapping breaks clickable links
            if _URL_RE.search(line):
                print("    " + _linkify(line))
                continue
            # Linkify before wrapping in case of inline URLs
            line = _linkify(line)
            # Preserve indented lines (code blocks, lists) without re-wrapping
            indent = len(line) - len(line.lstrip())
            if indent > 0 or len(line) <= tw:
                print("    " + line)
            else:
                for wrapped in textwrap.wrap(line, width=tw, subsequent_indent="    "):
                    print("    " + wrapped)
        else:
            print()


def _slash_model() -> str | None:
    """
    /model slash command handler.
    Fetches available models, shows a numbered list with the active model
    highlighted, lets the user pick new flash and pro models, then:
      1. Updates os.environ immediately (affects this process).
      2. Mutates root_agent.model in place so the change takes effect on
         the very next message — no restart needed.
      3. Writes MODEL_ID / PLANNING_MODEL_ID to .env for future sessions.

    Returns the new MODEL_ID string if changed, else None.
    """
    sys.path.insert(0, os.path.dirname(__file__) or ".")
    try:
        from scripts.discover_models import (
            discover_models, print_model_table,
            select_models_interactive, write_env_models,
        )
    except ImportError as exc:
        _err(f"Cannot import discover_models: {exc}")
        return None

    print()
    with _Spinner("Querying available models..."):
        try:
            models = discover_models()
        except Exception as exc:
            _err(str(exc))
            return None

    current_flash = os.environ.get("MODEL_ID", "")
    current_pro   = os.environ.get("PLANNING_MODEL_ID", "")
    print_model_table(models, current_flash, current_pro)

    selected  = select_models_interactive(models)
    new_flash = selected.get("flash", current_flash)
    new_pro   = selected.get("pro",   current_pro)

    if new_flash == current_flash and new_pro == current_pro:
        _hint("No change.")
        return None

    # Update process environment for any code that reads it after this point
    if new_flash:
        os.environ["MODEL_ID"] = new_flash
    if new_pro:
        os.environ["PLANNING_MODEL_ID"] = new_pro

    # Try to mutate root_agent.model in place — makes the change live immediately
    # without restarting the session
    live = False
    try:
        from app.agent import root_agent
        root_agent.model = new_flash
        live = True
    except Exception:
        pass

    # Persist to .env so future sessions inherit the choice
    env_path = os.path.join(os.path.dirname(__file__) or ".", ".env")
    try:
        write_env_models(new_flash or current_flash, new_pro or current_pro, env_path)
    except Exception:
        pass

    print()
    suffix = " — active now" if live else f" — saved to {env_path}, restart to apply"
    _ok("Model updated" + suffix)
    kw = 14
    print(f"  {_c('Flash'.ljust(kw), _GREY)}  {_c(new_flash, _CYAN)}")
    print(f"  {_c('Pro (planning)'.ljust(kw), _GREY)}  {_c(new_pro, _CYAN)}")
    print()
    return new_flash


async def _chat_loop(org_id: str, customer_id: str) -> None:
    from google.adk.runners import InMemoryRunner

    # Load the agent (triggers app/__init__.py env setup)
    import app  # noqa: F401
    from app.agent import root_agent

    model_id = os.environ.get("MODEL_ID", "gemini-2.0-flash-preview")

    runner = InMemoryRunner(agent=root_agent, app_name="scc-agent")
    session = await runner.session_service.create_session(
        app_name="scc-agent",
        user_id="cli",
        state={"org_id": org_id, "customer_id": customer_id},
    )

    total_tokens  = 0
    prompt_tokens = 0
    output_tokens = 0
    turn          = 0
    start_time    = time.time()

    # ── Header ──────────────────────────────────────────────────────────
    print()
    print(f"  {_c('scc-agent', _BOLD, _WHITE)}  {_c('chat', _CYAN)}")
    print()
    kw = 10
    for k, v in [("org", org_id), ("customer", customer_id or "—"), ("model", model_id)]:
        print(f"  {_c(k.ljust(kw), _GREY)}  {v}")
    print()
    print(_c("  Type a message or instruction. /help for commands. Ctrl+C to exit.", _GREY))
    _divider()

    # ── Initial proactive turn ───────────────────────────────────────────
    # Seed the agent with context and ask it to proactively fetch findings.
    seed = (
        f"org_id={org_id}"
        + (f", customer_id={customer_id}" if customer_id else "")
        + ". List the top priority active findings now."
    )
    turn += 1
    resp, p_tok, o_tok = await _run_agent_turn(
        runner, session, seed, "Fetching top priority findings..."
    )
    _print_agent_response(resp)
    prompt_tokens += p_tok
    output_tokens += o_tok
    total_tokens  += p_tok + o_tok
    elapsed = int(time.time() - start_time)
    print()
    print(_stats_line(turn, total_tokens, elapsed, model_id))

    # ── REPL ────────────────────────────────────────────────────────────
    while True:
        try:
            print()
            user_input = input(_c("  You  › ", _BOLD, _CYAN)).strip()
        except (KeyboardInterrupt, EOFError):
            print()
            _divider()
            _print_session_summary(turn, total_tokens, prompt_tokens, output_tokens, start_time, model_id)
            return

        if not user_input:
            continue

        # Slash commands
        if user_input.startswith("/"):
            cmd = user_input.lstrip("/").split()[0].lower()
            rest = user_input[len(cmd) + 2:].strip()
            if cmd in ("exit", "quit"):
                _divider()
                _print_session_summary(turn, total_tokens, prompt_tokens, output_tokens, start_time, model_id)
                return
            if cmd == "help":
                print(_SLASH_HELP)
                continue
            if cmd == "clear":
                print("\033[2J\033[H", end="")
                continue
            if cmd == "model":
                new_m = _slash_model()
                if new_m:
                    model_id = new_m
                continue
            if cmd == "status" and customer_id:
                approvals = _get_approvals_local(customer_id, "PENDING", limit=10)
                if approvals:
                    rows = [
                        {
                            "id":       (a.get("approval_id", "")[:12] + "…"),
                            "severity": a.get("severity", ""),
                            "blast":    a.get("blast_level", ""),
                            "asset":    (a.get("asset_name", "") or "").split("/")[-1][:28],
                            "age":      _relative_time(a.get("created_at")),
                        }
                        for a in approvals
                    ]
                    print()
                    _print_table(rows, [
                        ("ID", "id"), ("SEVERITY", "severity"),
                        ("BLAST", "blast"), ("ASSET", "asset"), ("AGE", "age"),
                    ])
                else:
                    print("  No pending approvals.")
                continue
            if cmd == "finding" and rest:
                org = org_id or os.environ.get("ORG_ID", "")
                finding = _get_finding_local(rest, org)
                if finding:
                    print()
                    _panel("Finding", [
                        ("ID",       rest),
                        ("Resource", finding.get("resource_name", "—")),
                        ("Category", finding.get("category", "—")),
                        ("Severity", _severity_badge(finding.get("severity", "—"))),
                        ("State",    _status_color(finding.get("state", "—"))),
                    ])
                continue
            _hint(f"Unknown command /{cmd}. Type /help.")
            continue

        # Agent turn
        turn += 1
        try:
            resp, p_tok, o_tok = await _run_agent_turn(runner, session, user_input)
        except KeyboardInterrupt:
            print()
            _divider()
            _print_session_summary(turn - 1, total_tokens, prompt_tokens, output_tokens, start_time, model_id)
            return
        _print_agent_response(resp)
        prompt_tokens += p_tok
        output_tokens += o_tok
        total_tokens  += p_tok + o_tok
        elapsed = int(time.time() - start_time)
        print()
        print(_stats_line(turn, total_tokens, elapsed, model_id))


def cmd_chat(args):
    if args.api_url:
        _err("chat is local-only.")
        sys.exit(1)

    org_id      = args.org_id      or os.environ.get("ORG_ID", "")
    customer_id = args.customer_id or os.environ.get("CUSTOMER_ID", "")
    if not org_id:
        _err("--org-id is required for chat (or set ORG_ID).")
        sys.exit(1)

    try:
        asyncio.run(_chat_loop(org_id, customer_id))
    except (KeyboardInterrupt, asyncio.CancelledError):
        pass


def cmd_status(args):
    customer_id = args.customer_id or os.environ.get("CUSTOMER_ID")
    if not customer_id:
        _err("--customer-id is required.")
        sys.exit(1)

    status_filter = getattr(args, "filter", None)

    with _Spinner("Fetching approvals..."):
        if args.api_url:
            token = _get_id_token(args.api_url)
            params = f"?status={status_filter}" if status_filter else ""
            approvals = _http("GET", f"{args.api_url}/api/approvals/{customer_id}{params}", token=token)
        else:
            approvals = _get_approvals_local(customer_id, status_filter, getattr(args, "limit", 20))

    if args.format == "json":
        print(json.dumps(approvals, indent=2, default=str))
        return

    _header(f"status  ·  {customer_id}")

    if not approvals:
        label = f" ({status_filter})" if status_filter else ""
        print(f"  No approvals found{label}.")
        _hint("Run  scc-agent run --customer-id " + customer_id + "  to start a cycle.")
        print()
        return

    # Summary counts
    counts: dict[str, int] = {}
    for a in approvals:
        s = a.get("status", "UNKNOWN")
        counts[s] = counts.get(s, 0) + 1

    summary_parts = []
    for s, n in sorted(counts.items()):
        summary_parts.append(_status_color(s) + _c(f" {n}", _BOLD))
    print("  " + "   ".join(summary_parts))
    print()

    rows = [
        {
            "id":       (a.get("approval_id", "")[:12] + "…"),
            "severity": a.get("severity", ""),
            "status":   a.get("status", ""),
            "blast":    a.get("blast_level", ""),
            "tier":     f"T{a.get('execution_tier', a.get('tier', '?'))}",
            "asset":    (a.get("asset_name", "") or "").split("/")[-1][:28],
            "age":      _relative_time(a.get("created_at")),
        }
        for a in approvals
    ]
    _print_table(rows, [
        ("ID",       "id"),
        ("SEVERITY", "severity"),
        ("STATUS",   "status"),
        ("BLAST",    "blast"),
        ("TIER",     "tier"),
        ("ASSET",    "asset"),
        ("AGE",      "age"),
    ])
    print()
    _hint(f"{len(approvals)} approval(s) shown" + (f"  ·  filter: {status_filter}" if status_filter else ""))
    _hint("scc-agent approve <id>  ·  scc-agent reject <id>  ·  scc-agent finding <id>")
    print()


def cmd_approve(args):
    approval_id = args.approval_id
    customer_id = args.customer_id or os.environ.get("CUSTOMER_ID", "")
    actor       = args.actor or os.environ.get("USER", "cli-user")

    if args.api_url:
        # Remote: fetch details for preview first
        token = _get_id_token(args.api_url)
        try:
            detail = _http("GET", f"{args.api_url}/api/approvals/{approval_id}", token=token)
            _print_approval_preview(detail)
        except SystemExit:
            pass  # detail fetch failed, proceed without preview
        if not args.yes and not _confirm(f"Approve this remediation as {actor}?"):
            print("  Aborted.")
            return
        result = _http("POST", f"{args.api_url}/api/approvals/{approval_id}/approve",
                       {"actor": actor}, token)
    else:
        # Local: fetch record before updating so we can show preview
        db = _firestore_client()
        doc = db.collection("approvals").document(approval_id).get()
        if doc.exists:
            _print_approval_preview(doc.to_dict() | {"approval_id": approval_id})
        if not args.yes and not _confirm(f"Approve this remediation as {actor}?"):
            print("  Aborted.")
            return
        result = _update_approval_local(approval_id, customer_id, "approve", actor)

    if args.format == "json":
        print(json.dumps({k: v for k, v in result.items() if k != "_data"}, indent=2, default=str))
    else:
        print()
        _ok(f"Approved  {approval_id}")
        _hint(f"Responded by: {actor}")
        print()


def cmd_reject(args):
    approval_id = args.approval_id
    customer_id = args.customer_id or os.environ.get("CUSTOMER_ID", "")
    actor       = args.actor or os.environ.get("USER", "cli-user")

    if args.api_url:
        token = _get_id_token(args.api_url)
        try:
            detail = _http("GET", f"{args.api_url}/api/approvals/{approval_id}", token=token)
            _print_approval_preview(detail)
        except SystemExit:
            pass
        if not args.yes and not _confirm(f"Reject this remediation as {actor}?"):
            print("  Aborted.")
            return
        result = _http("POST", f"{args.api_url}/api/approvals/{approval_id}/reject",
                       {"actor": actor}, token)
    else:
        db = _firestore_client()
        doc = db.collection("approvals").document(approval_id).get()
        if doc.exists:
            _print_approval_preview(doc.to_dict() | {"approval_id": approval_id})
        if not args.yes and not _confirm(f"Reject this remediation as {actor}?"):
            print("  Aborted.")
            return
        result = _update_approval_local(approval_id, customer_id, "reject", actor)

    if args.format == "json":
        print(json.dumps({k: v for k, v in result.items() if k != "_data"}, indent=2, default=str))
    else:
        print()
        _err(f"Rejected  {approval_id}")
        _hint(f"Responded by: {actor}")
        print()


def cmd_rollback(args):
    approval_id = args.approval_id

    # Fetch details for preview before confirming
    if not args.api_url:
        db = _firestore_client()
        doc = db.collection("approvals").document(approval_id).get()
        if doc.exists:
            _print_approval_preview(doc.to_dict() | {"approval_id": approval_id})

    if not args.yes:
        _warn("This will undo all changes made by the remediation.")
        if not _confirm(f"Roll back {approval_id}?"):
            print("  Aborted.")
            return

    with _Spinner("Executing rollback..."):
        if args.api_url:
            token = _get_id_token(args.api_url)
            result = _http("POST", f"{args.api_url}/api/rollback/{approval_id}", token=token)
        else:
            result = _rollback_local(approval_id)

    if args.format == "json":
        print(json.dumps(result, indent=2, default=str))
        return

    status = result.get("status", "")
    print()
    if status == "SUCCESS":
        _ok(f"Rollback succeeded  ·  {approval_id}")
    else:
        _err(f"Rollback failed: {result.get('output', 'unknown error')}")

    if result.get("steps_reversed"):
        _hint(f"Steps reversed: {result['steps_reversed']}")
    print()


def cmd_finding(args):
    finding_id = args.finding_id
    org_id     = args.org_id or os.environ.get("ORG_ID", "")

    with _Spinner(f"Fetching {finding_id}..."):
        if args.api_url:
            token   = _get_id_token(args.api_url)
            finding = _http("GET", f"{args.api_url}/api/findings/{finding_id}", token=token)
        else:
            if not org_id:
                _err("--org-id is required for local finding lookup (or set ORG_ID).")
                sys.exit(1)
            finding = _get_finding_local(finding_id, org_id)
            if not finding:
                _err(f"Finding {finding_id} not found.")
                sys.exit(1)

    if args.format == "json":
        print(json.dumps(finding, indent=2, default=str))
        return

    print()

    rows: list[tuple[str, str]] = [
        ("Finding",  finding_id),
        ("Resource", finding.get("resource_name", "—")),
        ("Category", finding.get("category", "—")),
        ("Severity", _severity_badge(finding.get("severity", "—"))),
        ("State",    _status_color(finding.get("state", finding.get("status", "—")))),
    ]
    if finding.get("cve_ids"):
        rows.append(("CVEs", ", ".join(finding["cve_ids"])))
    if finding.get("attack_exposure_score") is not None:
        rows.append(("Attack exposure", str(finding["attack_exposure_score"])))
    if finding.get("remediation_text"):
        guidance = textwrap.shorten(finding["remediation_text"], width=60, placeholder="…")
        rows.append(("Guidance", guidance))

    _panel("Finding details", rows)
    print()


# ---------------------------------------------------------------------------
# Shared UI helpers
# ---------------------------------------------------------------------------

def _print_approval_preview(a: dict) -> None:
    """Renders a panel summarising an approval before a confirmation prompt."""
    print()
    rows: list[tuple[str, str]] = [
        ("Approval",  (a.get("approval_id", ""))[:16] + "…"),
        ("Asset",     (a.get("asset_name", "—") or "—").split("/")[-1]),
        ("Severity",  _severity_badge(a.get("severity", "—"))),
        ("Blast",     _blast_badge(a.get("blast_level", "—"))),
        ("Tier",      f"T{a.get('execution_tier', a.get('tier', '?'))}"),
        ("Status",    _status_color(a.get("status", "—"))),
    ]
    if a.get("plan_summary") or (a.get("plan") and a["plan"].get("summary")):
        summary = a.get("plan_summary") or a["plan"]["summary"]
        rows.append(("Plan", textwrap.shorten(summary, width=56, placeholder="…")))
    if a.get("confidence_score") is not None:
        rows.append(("Confidence", f"{a['confidence_score']:.0%}"))
    _panel("Approval", rows)


def _confirm(prompt: str) -> bool:
    """Prints a prompt and returns True if user answers y/yes."""
    try:
        answer = input(_c(f"\n  {prompt} ", _BOLD) + _c("[y/N]  ", _GREY))
        return answer.strip().lower() in ("y", "yes")
    except (KeyboardInterrupt, EOFError):
        print()
        return False


def _relative_time(ts) -> str:
    """Returns a human-readable relative timestamp like '2h ago'."""
    if ts is None:
        return "—"
    try:
        if hasattr(ts, "timestamp"):
            dt = ts
        else:
            dt = datetime.datetime.fromisoformat(str(ts))
        delta = datetime.datetime.utcnow() - dt.replace(tzinfo=None)
        secs = int(delta.total_seconds())
        if secs < 60:
            return f"{secs}s ago"
        if secs < 3600:
            return f"{secs // 60}m ago"
        if secs < 86400:
            return f"{secs // 3600}h ago"
        return f"{secs // 86400}d ago"
    except Exception:
        return str(ts)[:16]


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
              scc-agent chat
              scc-agent run --customer-id acme-prod
              scc-agent status --customer-id acme-prod --filter PENDING
              scc-agent approve apv-abc123 --customer-id acme-prod
              scc-agent reject  apv-abc123 --customer-id acme-prod
              scc-agent rollback apv-abc123
              scc-agent finding  find-001 --org-id 123456789
              scc-agent status --api-url https://scheduler-abc.run.app --customer-id acme-prod
        """),
    )

    # Global options on the main parser (apply when placed BEFORE the subcommand).
    # They are also added to every subparser below so they work in either position:
    #   scc-agent --org-id X chat          ← before subcommand
    #   scc-agent chat --org-id X          ← after subcommand (also works)
    _G = dict(default=argparse.SUPPRESS)   # don't override the parent default
    parser.add_argument("--customer-id", help="Customer ID (env: CUSTOMER_ID)")
    parser.add_argument("--org-id",      help="GCP org ID (env: ORG_ID)")
    parser.add_argument("--api-url",     help="Deployed scheduler base URL — enables remote mode")
    parser.add_argument("--format",      choices=["table", "json"], default="table",
                        help="Output format (default: table)")

    sub = parser.add_subparsers(dest="command", metavar="command")
    sub.required = True

    def _add_globals(p):
        """Attach global options to a subparser so they work after the subcommand."""
        p.add_argument("--customer-id", **_G)
        p.add_argument("--org-id",      **_G)
        p.add_argument("--api-url",     **_G)
        p.add_argument("--format",      choices=["table", "json"], **_G)

    run_p  = sub.add_parser("run",  help="Run the full remediation batch cycle")
    _add_globals(run_p)

    models_p = sub.add_parser("models", help="List available Gemini models and optionally select new defaults")
    _add_globals(models_p)
    models_p.add_argument("--select", action="store_true", help="Interactively pick models and save to .env")

    chat_p = sub.add_parser("chat", help="Start interactive CLI session (local only)")
    _add_globals(chat_p)

    status_p = sub.add_parser("status", help="Show approvals and recent activity")
    _add_globals(status_p)
    status_p.add_argument("--filter", metavar="STATUS",
                          help="Filter by status: PENDING, APPROVED, REJECTED, BLOCKED, DEFERRED")
    status_p.add_argument("--limit", type=int, default=20, help="Max rows (default: 20)")

    approve_p = sub.add_parser("approve", help="Approve a pending remediation")
    _add_globals(approve_p)
    approve_p.add_argument("approval_id")
    approve_p.add_argument("--actor", help="Approver identity (default: $USER)")
    approve_p.add_argument("-y", "--yes", action="store_true", help="Skip confirmation prompt")

    reject_p = sub.add_parser("reject", help="Reject a pending remediation")
    _add_globals(reject_p)
    reject_p.add_argument("approval_id")
    reject_p.add_argument("--actor", help="Rejecter identity (default: $USER)")
    reject_p.add_argument("-y", "--yes", action="store_true", help="Skip confirmation prompt")

    rollback_p = sub.add_parser("rollback", help="Roll back an executed remediation (24 h window)")
    _add_globals(rollback_p)
    rollback_p.add_argument("approval_id")
    rollback_p.add_argument("-y", "--yes", action="store_true", help="Skip confirmation prompt")

    finding_p = sub.add_parser("finding", help="Show SCC finding details")
    _add_globals(finding_p)
    finding_p.add_argument("finding_id")

    return parser


def main():
    parser = _build_parser()
    args   = parser.parse_args()

    dispatch = {
        "run":      cmd_run,
        "models":   cmd_models,
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
