"""
Context budget management — Layer 1 compaction.

Implements the budget-reduction layer from the Claude Code harness architecture
(arXiv 2604.14228): enforces per-section character limits before injecting data
into agent prompts. Prevents oversized CAI resource payloads from silently
overflowing the context window and producing cryptic API errors.

Three-stage strategy per section (cheapest → most aggressive):
  1. Full indent=2 serialisation  — return immediately if within budget
  2. Field pruning + compact JSON  — remove known-verbose fields, truncate
                                     long lists, re-serialise without indent
  3. Hard character truncation     — last resort; appends a truncation marker
                                     so the model knows data was cut

Per-section budgets (characters, not tokens) are tunable via env vars.
Rule of thumb: 1 token ≈ 4 chars for English/JSON.

Usage:
    from app.tools.context_budget import budget_json, BUDGETS

    resource_section = budget_json(resource_data, BUDGETS["resource_data"], "resource_data")
    impact_section   = budget_json(impact,        BUDGETS["impact"],        "impact")
"""

import json
import os

# ---------------------------------------------------------------------------
# Per-section character budgets
# ---------------------------------------------------------------------------

BUDGETS: dict[str, int] = {
    # CAI resource.data blob — the highest-risk overflow source.
    # GKE clusters / VPCs can return 200K+ chars of raw JSON.
    "resource_data": int(os.environ.get("CONTEXT_BUDGET_RESOURCE_DATA", "32000")),
    # Impact analysis output — graph traversal results
    "impact":        int(os.environ.get("CONTEXT_BUDGET_IMPACT",        "16000")),
    # Pre-flight check results — small by design, but cap defensively
    "preflight":     int(os.environ.get("CONTEXT_BUDGET_PREFLIGHT",      "8000")),
    # SCC finding JSON — typically small; cap protects against custom fields
    "finding":       int(os.environ.get("CONTEXT_BUDGET_FINDING",        "4000")),
}

# ---------------------------------------------------------------------------
# Verbose fields to strip in the pruning stage
# ---------------------------------------------------------------------------

# Scalar fields that consume tokens without helping the LLM plan a remediation
_PRUNE_SCALAR_FIELDS = frozenset({
    "selfLink",
    "kind",
    "etag",
    "fingerprint",
    "creationTimestamp",
    # GCE numeric resource ID — name/labels are more useful
    "id",
})

# List fields whose entries are repetitive and rarely affect plan content
_PRUNE_LIST_FIELDS = frozenset({
    # GCE instance metadata items often contain multi-KB startup scripts
    "items",
    # GKE node pool upgrade settings — not relevant to remediation
    "upgradeSettings",
    # VPC route tables — can have hundreds of entries
    "routes",
    # Billing / usage export config
    "usageExportBucket",
})

_MAX_LIST_ITEMS = 5  # keep first N items from any list, append a count marker


# ---------------------------------------------------------------------------
# Stage 2 helper: field pruning
# ---------------------------------------------------------------------------

def _slim(data, depth: int = 0):
    """
    Recursively prune verbose fields and cap long lists.
    Applied before hard truncation to preserve maximum semantic content.
    """
    if isinstance(data, dict):
        out = {}
        for key, value in data.items():
            if key in _PRUNE_SCALAR_FIELDS:
                continue
            # Strip GCE metadata.items (startup scripts, sshKeys, etc.)
            if key == "metadata" and isinstance(value, dict):
                value = {k: v for k, v in value.items() if k not in _PRUNE_LIST_FIELDS}
            out[key] = _slim(value, depth + 1)
        return out

    if isinstance(data, list):
        if len(data) > _MAX_LIST_ITEMS:
            slimmed = [_slim(x, depth + 1) for x in data[:_MAX_LIST_ITEMS]]
            slimmed.append(f"[... {len(data) - _MAX_LIST_ITEMS} more items not shown]")
            return slimmed
        return [_slim(x, depth + 1) for x in data]

    return data


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

def budget_json(data: dict | list, max_chars: int, label: str) -> str:
    """
    Serialises *data* to a JSON string within *max_chars*.

    Stage 1 — pretty print (indent=2). If it fits, return as-is.
    Stage 2 — strip verbose fields + compact serialisation. If it fits, return.
    Stage 3 — hard truncate at max_chars with an explanatory marker appended.

    Args:
        data:      The dict or list to serialise.
        max_chars: Maximum number of characters in the returned string.
        label:     Short name used in the truncation marker and env var name.

    Returns:
        A JSON string (or partial JSON string) within max_chars.
    """
    # Stage 1: full pretty-print
    full = json.dumps(data, indent=2, default=str)
    if len(full) <= max_chars:
        return full

    # Stage 2: prune + compact
    compact = json.dumps(_slim(data), default=str)
    if len(compact) <= max_chars:
        return compact

    # Stage 3: hard truncate
    removed = len(compact) - max_chars
    marker = (
        f"\n[CONTEXT_BUDGET: '{label}' section truncated — {removed:,} chars removed. "
        f"Set CONTEXT_BUDGET_{label.upper()} env var to increase the limit.]"
    )
    # Leave room for the marker itself
    cut = max(0, max_chars - len(marker))
    return compact[:cut] + marker


def budget_str(text: str, max_chars: int, label: str) -> str:
    """
    Enforces a character budget on a plain string (e.g. remediation_text).
    """
    if len(text) <= max_chars:
        return text
    removed = len(text) - max_chars
    marker = f"[... {removed:,} chars truncated]"
    cut = max(0, max_chars - len(marker))
    return text[:cut] + marker
