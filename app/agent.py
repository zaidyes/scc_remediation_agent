"""
ADK agent definitions for the SCC Remediation Agent.

Tool pool assembly follows the Claude Code harness pattern (arXiv 2604.14228):
each sub-agent receives only the tools relevant to its role and the remediation
type being processed — reducing context cost and eliminating wrong-tool
hallucinations.

Assembly pipeline (3 of the paper's 5 steps; MCP/dedup added when needed):
  1. Base enumeration  — all available tools per agent role
  2. Type filtering    — restrict to tools relevant for the remediation type
  3. Deny-rule filter  — strip any tool blocked by the deny list

Static module-level agents (root_agent, triage_agent, verify_agent) are used by
agents-cli and ADK interactive mode. build_impact_agent() and build_plan_agent()
return type-specific instances for the batch pipeline (app/agents/*.py).
"""
import os
from typing import Literal

from google.adk.agents import Agent
from google.adk.tools import FunctionTool

from app.tools.scc_tools import get_finding_detail, mute_resolved_finding, list_active_findings
from app.tools.graph_tools import (
    query_blast_radius,
    query_iam_paths,
    check_dormancy,
    query_dependency_chain,
)
from app.tools.network_tools import get_network_exposure
from app.tools.osconfig_tools import create_patch_job
from app.tools.approval_tools import dispatch_approval_request
from app.tools.validate_plan_tool import validate_plan
from app.prompts import (
    TRIAGE_AGENT_INSTRUCTION,
    IMPACT_AGENT_INSTRUCTION,
    PLAN_AGENT_INSTRUCTION,
    VERIFY_AGENT_INSTRUCTION,
    ROOT_AGENT_INSTRUCTION,
)

_MODEL = os.getenv("MODEL_ID", "gemini-2.5-flash")
_PLANNING_MODEL = os.getenv("PLANNING_MODEL_ID", "gemini-2.5-pro")

RemediationType = Literal["OS_PATCH", "FIREWALL", "IAM", "MISCONFIGURATION"] | None

# ---------------------------------------------------------------------------
# Tool pool definitions — Step 1: base enumeration + Step 2: type filtering
# ---------------------------------------------------------------------------
#
# Each pool contains only the tools that are meaningful for that remediation type.
# Tools that are irrelevant to a type add schema tokens to every model call with
# no benefit, and create surface area for the model to call the wrong tool.
#
# Key decisions:
#   OS_PATCH    — blast radius + dependency chain to find prod dependents;
#                 NO IAM paths (not relevant for patch planning);
#                 NO network exposure (not a connectivity change)
#   IAM         — blast radius + IAM paths for lateral movement analysis;
#                 NO network exposure; NO dependency chain (graph traversal
#                 for IAM findings is about permission, not infra deps)
#   FIREWALL    — blast radius + network exposure + dependency chain;
#                 NO IAM paths (firewall rules don't change IAM bindings)
#   MISCONFIGURATION — all tools; findings span many resource types
#
# The root_agent's impact sub-agents include all four types so ADK's routing
# LLM can select the right one based on the finding description.

_IMPACT_TOOL_POOLS: dict[str | None, list] = {
    "OS_PATCH": [
        FunctionTool(query_blast_radius),
        FunctionTool(query_dependency_chain),
        FunctionTool(check_dormancy),
    ],
    "IAM": [
        FunctionTool(query_blast_radius),
        FunctionTool(query_iam_paths),
        FunctionTool(check_dormancy),
    ],
    "FIREWALL": [
        FunctionTool(query_blast_radius),
        FunctionTool(query_dependency_chain),
        FunctionTool(get_network_exposure),
    ],
    "MISCONFIGURATION": [
        FunctionTool(query_blast_radius),
        FunctionTool(query_iam_paths),
        FunctionTool(check_dormancy),
        FunctionTool(query_dependency_chain),
        FunctionTool(get_network_exposure),
    ],
    # None = no type known; use full pool (interactive / ADK fallback)
    None: [
        FunctionTool(query_blast_radius),
        FunctionTool(query_iam_paths),
        FunctionTool(check_dormancy),
        FunctionTool(query_dependency_chain),
        FunctionTool(get_network_exposure),
    ],
}

# Root agent tools — dispatch_approval_request is always present;
# get_finding_detail is on root so "tell me more" stays with root and doesn't
# route to triage_agent (which always outputs JSON);
# create_patch_job is OS_PATCH only.
_LIST_FINDINGS_TOOL        = FunctionTool(list_active_findings)
_GET_FINDING_TOOL          = FunctionTool(get_finding_detail)
_VALIDATE_PLAN_TOOL        = FunctionTool(validate_plan)
_BLAST_RADIUS_TOOL         = FunctionTool(query_blast_radius)
_DEPENDENCY_CHAIN_TOOL     = FunctionTool(query_dependency_chain)
_IAM_PATHS_TOOL            = FunctionTool(query_iam_paths)
_NETWORK_EXPOSURE_TOOL     = FunctionTool(get_network_exposure)

# Root agent ad-hoc query tools — present on root so the model can answer
# dependency/exposure questions directly when a user asks outside the formal
# pipeline (e.g. "what services depend on this rule?").
_ROOT_ADHOC_TOOLS = [
    _BLAST_RADIUS_TOOL,
    _DEPENDENCY_CHAIN_TOOL,
    _IAM_PATHS_TOOL,
    _NETWORK_EXPOSURE_TOOL,
]

_ROOT_TOOL_POOLS: dict[str | None, list] = {
    "OS_PATCH": [
        _LIST_FINDINGS_TOOL,
        _GET_FINDING_TOOL,
        _VALIDATE_PLAN_TOOL,
        _BLAST_RADIUS_TOOL,
        _DEPENDENCY_CHAIN_TOOL,
        FunctionTool(dispatch_approval_request),
        FunctionTool(create_patch_job),
    ],
    "IAM": [
        _LIST_FINDINGS_TOOL,
        _GET_FINDING_TOOL,
        _VALIDATE_PLAN_TOOL,
        _BLAST_RADIUS_TOOL,
        _IAM_PATHS_TOOL,
        FunctionTool(dispatch_approval_request),
    ],
    "FIREWALL": [
        _LIST_FINDINGS_TOOL,
        _GET_FINDING_TOOL,
        _VALIDATE_PLAN_TOOL,
        _BLAST_RADIUS_TOOL,
        _DEPENDENCY_CHAIN_TOOL,
        _NETWORK_EXPOSURE_TOOL,
        FunctionTool(dispatch_approval_request),
    ],
    "MISCONFIGURATION": [
        _LIST_FINDINGS_TOOL,
        _GET_FINDING_TOOL,
        _VALIDATE_PLAN_TOOL,
        *_ROOT_ADHOC_TOOLS,
        FunctionTool(dispatch_approval_request),
    ],
    None: [
        _LIST_FINDINGS_TOOL,
        _GET_FINDING_TOOL,
        _VALIDATE_PLAN_TOOL,
        *_ROOT_ADHOC_TOOLS,
        FunctionTool(dispatch_approval_request),
        FunctionTool(create_patch_job),
    ],
}

# ---------------------------------------------------------------------------
# Step 3: Deny-rule filter
# ---------------------------------------------------------------------------
# Tools listed here are stripped from every pool regardless of type.
# Add tool function names to block them globally (e.g. during incident mode).

_DENY_LIST: frozenset[str] = frozenset(
    t.strip()
    for t in os.environ.get("AGENT_TOOL_DENY_LIST", "").split(",")
    if t.strip()
)


def _apply_deny_list(tools: list) -> list:
    """Removes any FunctionTool whose underlying function name is in _DENY_LIST."""
    if not _DENY_LIST:
        return tools
    return [t for t in tools if t.func.__name__ not in _DENY_LIST]


# ---------------------------------------------------------------------------
# Agent factories
# ---------------------------------------------------------------------------

def build_impact_agent(remediation_type: RemediationType = None) -> Agent:
    """
    Returns an impact Agent with a tool pool scoped to the remediation type.
    Called by the batch pipeline (app/agents/impact_agent.py) to avoid
    passing irrelevant tools to the model.
    """
    tools = _apply_deny_list(_IMPACT_TOOL_POOLS.get(remediation_type, _IMPACT_TOOL_POOLS[None]))
    type_label = remediation_type or "general"
    return Agent(
        model=_MODEL,
        name=f"impact_agent_{type_label.lower()}",
        description=(
            f"Blast-radius analysis for {type_label} findings: "
            + {
                "OS_PATCH":         "downstream dependencies and asset dormancy.",
                "IAM":              "lateral movement paths and permission exposure.",
                "FIREWALL":         "network exposure and connectivity impact.",
                "MISCONFIGURATION": "full graph traversal across all dimensions.",
            }.get(type_label, "graph traversal and exposure analysis.")
        ),
        instruction=IMPACT_AGENT_INSTRUCTION,
        tools=tools,
        output_key="impact_agent_output",
    )


def build_plan_agent(remediation_type: RemediationType = None) -> Agent:
    """
    Returns a plan Agent. Currently plan_agent uses no ADK tools (it makes
    direct Gemini calls in app/agents/plan_agent.py with pre-fetched data),
    but the factory is provided so type-specific planning instructions can
    be injected in future without changing call sites.
    """
    return Agent(
        model=_PLANNING_MODEL,
        name=f"plan_agent_{(remediation_type or 'general').lower()}",
        description=f"Generates a remediation plan for {remediation_type or 'any'} findings.",
        instruction=PLAN_AGENT_INSTRUCTION,
        tools=[],
        output_key="plan_agent_output",
    )


# ---------------------------------------------------------------------------
# Static agents — used by agents-cli and ADK interactive mode
# ---------------------------------------------------------------------------

triage_agent = Agent(
    model=_MODEL,
    name="triage_agent",
    description="Assesses SCC finding scope, severity, dormancy and attack exposure.",
    instruction=TRIAGE_AGENT_INSTRUCTION,
    tools=_apply_deny_list([
        FunctionTool(get_finding_detail),
        FunctionTool(check_dormancy),
    ]),
    output_key="triage_agent_output",
)

# For interactive mode: one impact agent per finding type — ADK's routing LLM
# picks the right one based on the finding's category description.
_impact_agent_os_patch      = build_impact_agent("OS_PATCH")
_impact_agent_iam           = build_impact_agent("IAM")
_impact_agent_firewall      = build_impact_agent("FIREWALL")
_impact_agent_misconfiguration = build_impact_agent("MISCONFIGURATION")

plan_agent = build_plan_agent()

verify_agent = Agent(
    model=_MODEL,
    name="verify_agent",
    description="Confirms remediation success and mutes resolved SCC findings.",
    instruction=VERIFY_AGENT_INSTRUCTION,
    tools=_apply_deny_list([
        FunctionTool(get_finding_detail),
        FunctionTool(mute_resolved_finding),
    ]),
    output_key="verify_agent_output",
)

root_agent = Agent(
    model=_MODEL,
    name="scc_remediation_agent",
    description=(
        "Orchestrates triage, impact analysis, remediation planning and verification "
        "for GCP Security Command Center findings."
    ),
    instruction=ROOT_AGENT_INSTRUCTION,
    tools=_apply_deny_list(_ROOT_TOOL_POOLS[None]),
    sub_agents=[
        triage_agent,
        _impact_agent_os_patch,
        _impact_agent_iam,
        _impact_agent_firewall,
        _impact_agent_misconfiguration,
        plan_agent,
        verify_agent,
    ],
)
