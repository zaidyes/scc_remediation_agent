"""
discover_models.py — lists and ranks available Gemini Flash/Pro models.

Works with both Vertex AI (ADC) and AI Studio (GOOGLE_API_KEY).
Can be imported as a library or run standalone.

Standalone usage:
  uv run python scripts/discover_models.py          # list available models
  uv run python scripts/discover_models.py --select  # interactive selection → writes .env
  uv run python scripts/discover_models.py --json    # machine-readable output
"""
import os
import re
import sys
import json


# ---------------------------------------------------------------------------
# Version parsing
# ---------------------------------------------------------------------------

def _version_key(model_id: str) -> tuple:
    """
    Returns a sort key — lower tuple = newer/more capable (for ascending sort).

    Handles formats like:
      gemini-2.0-flash-001          → (2, 0, 0)  GA versioned
      gemini-2.5-flash              → (2, 5, 0)  GA
      gemini-2.5-flash-preview-09-2025 → (2, 5, 1)  dated preview
      gemini-3-flash-preview        → (3, 0, 2)  plain preview
      gemini-3.1-pro-preview        → (3, 1, 2)  plain preview
    """
    m = re.match(r"gemini-(\d+)(?:\.(\d+))?-", model_id)
    major = int(m.group(1)) if m else 0
    minor = int(m.group(2) or 0) if m else 0

    # Stability tier (lower = more stable = better)
    if "preview" not in model_id:
        stability = 0   # GA
    elif re.search(r"preview-\d{2}-\d{4}|preview-\d{4}", model_id):
        stability = 1   # dated preview (specific release)
    else:
        stability = 2   # plain preview

    return (-major, -minor, stability)  # negative so sorted() gives newest first


def _short_id(full_name: str) -> str:
    """Strips the 'publishers/google/models/' prefix if present."""
    return full_name.replace("publishers/google/models/", "").replace("models/", "")


# ---------------------------------------------------------------------------
# Discovery
# ---------------------------------------------------------------------------

_EXCLUDE_SUFFIXES = ("tts", "audio", "image", "lite", "embedding", "computer", "live")


def _is_flash(model_id: str) -> bool:
    return "flash" in model_id and not any(s in model_id for s in _EXCLUDE_SUFFIXES)


def _is_pro(model_id: str) -> bool:
    return ("pro" in model_id) and not any(s in model_id for s in _EXCLUDE_SUFFIXES)


def discover_models() -> dict[str, list[str]]:
    """
    Queries the API for available models and returns:
      {
        "flash": ["gemini-3-flash-preview", "gemini-2.5-flash", ...],   # newest first
        "pro":   ["gemini-3.1-pro-preview", "gemini-3-pro-preview", ...],
      }
    Raises on auth/network failure.
    """
    use_vertex = os.environ.get("GOOGLE_GENAI_USE_VERTEXAI", "True").lower() in ("true", "1")

    from google import genai
    if use_vertex:
        client = genai.Client()
    else:
        api_key = os.environ.get("GOOGLE_API_KEY", "")
        if not api_key:
            raise ValueError("GOOGLE_API_KEY not set and GOOGLE_GENAI_USE_VERTEXAI=False")
        client = genai.Client(api_key=api_key)

    raw = [_short_id(m.name) for m in client.models.list() if "gemini" in m.name]

    flash = sorted([m for m in raw if _is_flash(m)], key=_version_key)
    pro   = sorted([m for m in raw if _is_pro(m)],   key=_version_key)

    return {"flash": flash, "pro": pro}


# ---------------------------------------------------------------------------
# Formatting helpers (shared with CLI)
# ---------------------------------------------------------------------------

_RESET  = "\033[0m"
_BOLD   = "\033[1m"
_GREY   = "\033[90m"
_GREEN  = "\033[32m"
_CYAN   = "\033[36m"
_YELLOW = "\033[33m"


def _c(text: str, *codes: str) -> str:
    if not sys.stdout.isatty() or os.environ.get("NO_COLOR"):
        return text
    return "".join(codes) + text + _RESET


def _stability_label(model_id: str) -> str:
    if "preview" not in model_id:
        return _c("GA", _GREEN)
    if re.search(r"preview-\d{2}-\d{4}|preview-\d{4}", model_id):
        return _c("preview (dated)", _YELLOW)
    return _c("preview", _GREY)


def print_model_table(models: dict[str, list[str]], current_flash: str = "", current_pro: str = "") -> None:
    print()
    for role, label in [("flash", "Flash  (fast / triage)"), ("pro", "Pro  (planning / analysis)")]:
        items = models.get(role, [])
        print(_c(f"  {label}", _BOLD))
        if not items:
            print(_c("    (none found)", _GREY))
            continue
        for i, m in enumerate(items[:5]):  # show at most 5
            rank = ""
            if i == 0:
                rank = _c(" latest  ", _CYAN)
            elif i == 1:
                rank = _c(" latest-1", _GREY)
            else:
                rank = _c(f" older-{i-1} ", _GREY)

            current = _c("  ← current", _GREEN) if m in (current_flash, current_pro) else ""
            stab = _stability_label(m)
            print(f"    {rank}  {m:<45}  {stab}{current}")
        print()


# ---------------------------------------------------------------------------
# Interactive selection
# ---------------------------------------------------------------------------

def select_models_interactive(models: dict[str, list[str]]) -> dict[str, str]:
    """
    Prompts the user to pick a flash and a pro model.
    Returns {"flash": model_id, "pro": model_id}.
    """
    selected = {}
    for role, label in [("flash", "Flash (fast/triage)"), ("pro", "Pro (planning)")]:
        items = models.get(role, [])
        if not items:
            print(f"  No {role} models found — skipping.")
            continue

        print(_c(f"\n  {label} — pick a number:", _BOLD))
        for i, m in enumerate(items[:5], 1):
            tag = " (recommended)" if i == 1 else ""
            print(f"    {i}) {m}{_c(tag, _GREY)}")

        while True:
            try:
                raw = input(_c(f"\n  Choice [1–{min(5, len(items))}] (Enter = 1): ", _CYAN)).strip()
                idx = int(raw) - 1 if raw else 0
                if 0 <= idx < min(5, len(items)):
                    selected[role] = items[idx]
                    break
                print("  Invalid choice.")
            except (ValueError, KeyboardInterrupt, EOFError):
                selected[role] = items[0]
                break

    return selected


def write_env_models(flash: str, pro: str, env_path: str = ".env") -> None:
    """Updates MODEL_ID and PLANNING_MODEL_ID in the .env file."""
    try:
        with open(env_path) as f:
            lines = f.readlines()
    except FileNotFoundError:
        lines = []

    updated = {"MODEL_ID": False, "PLANNING_MODEL_ID": False}
    new_lines = []
    for line in lines:
        if line.startswith("MODEL_ID="):
            new_lines.append(f"MODEL_ID={flash}\n")
            updated["MODEL_ID"] = True
        elif line.startswith("PLANNING_MODEL_ID="):
            new_lines.append(f"PLANNING_MODEL_ID={pro}\n")
            updated["PLANNING_MODEL_ID"] = True
        else:
            new_lines.append(line)

    if not updated["MODEL_ID"]:
        new_lines.append(f"MODEL_ID={flash}\n")
    if not updated["PLANNING_MODEL_ID"]:
        new_lines.append(f"PLANNING_MODEL_ID={pro}\n")

    with open(env_path, "w") as f:
        f.writelines(new_lines)


# ---------------------------------------------------------------------------
# Standalone entry point
# ---------------------------------------------------------------------------

def main():
    import argparse
    parser = argparse.ArgumentParser(description="Discover available Gemini models")
    parser.add_argument("--select",  action="store_true", help="Interactively select models and write to .env")
    parser.add_argument("--json",    action="store_true", help="Output as JSON")
    parser.add_argument("--env",     default=".env",      help="Path to .env file (default: .env)")
    args = parser.parse_args()

    print(_c("\n  Querying available Gemini models...", _GREY), end=" ", flush=True)
    try:
        models = discover_models()
        print(_c("done", _GREEN))
    except Exception as exc:
        print(_c(f"failed: {exc}", "\033[31m"))
        sys.exit(1)

    if args.json:
        print(json.dumps(models, indent=2))
        return

    current_flash = os.environ.get("MODEL_ID", "")
    current_pro   = os.environ.get("PLANNING_MODEL_ID", "")
    print_model_table(models, current_flash, current_pro)

    if args.select:
        selected = select_models_interactive(models)
        flash = selected.get("flash", models["flash"][0] if models["flash"] else "")
        pro   = selected.get("pro",   models["pro"][0]   if models["pro"] else "")

        if flash or pro:
            write_env_models(flash, pro, args.env)
            print()
            print(_c("  Written to " + args.env + ":", _BOLD))
            print(f"    MODEL_ID={flash}")
            print(f"    PLANNING_MODEL_ID={pro}")
            print()
            print(_c("  Re-source .env or re-run local_test.sh to apply.", _GREY))
    else:
        latest_flash = models["flash"][0] if models["flash"] else ""
        latest_pro   = models["pro"][0]   if models["pro"] else ""
        print(_c("  To use the latest models:", _GREY))
        if latest_flash:
            print(_c(f"    export MODEL_ID={latest_flash}", _GREY))
        if latest_pro:
            print(_c(f"    export PLANNING_MODEL_ID={latest_pro}", _GREY))
        print(_c("  Or run with --select to pick interactively.", _GREY))
        print()


if __name__ == "__main__":
    main()
