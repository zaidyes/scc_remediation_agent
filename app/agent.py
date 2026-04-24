import os

from google.adk.agents import Agent
from google.adk.tools import FunctionTool

from app.tools.scc_tools import get_finding_detail, mute_resolved_finding
from app.tools.graph_tools import query_blast_radius, query_iam_paths, check_dormancy, query_dependency_chain
from app.tools.network_tools import get_network_exposure
from app.tools.osconfig_tools import create_patch_job
from app.tools.approval_tools import dispatch_approval_request
from app.prompts import (
    TRIAGE_AGENT_INSTRUCTION,
    IMPACT_AGENT_INSTRUCTION,
    PLAN_AGENT_INSTRUCTION,
    VERIFY_AGENT_INSTRUCTION,
    ROOT_AGENT_INSTRUCTION,
)

_MODEL = os.getenv("MODEL_ID", "gemini-3-flash-preview")
_PLANNING_MODEL = os.getenv("PLANNING_MODEL_ID", "gemini-3.1-pro-preview")

triage_agent = Agent(
    model=_MODEL,
    name="triage_agent",
    description="Assesses SCC finding scope, severity, dormancy and attack exposure.",
    instruction=TRIAGE_AGENT_INSTRUCTION,
    tools=[
        FunctionTool(get_finding_detail),
        FunctionTool(check_dormancy),
    ],
    output_key="triage_agent_output",
)

impact_agent = Agent(
    model=_MODEL,
    name="impact_agent",
    description="Performs blast-radius analysis: downstream deps, IAM paths, network exposure.",
    instruction=IMPACT_AGENT_INSTRUCTION,
    tools=[
        FunctionTool(query_blast_radius),
        FunctionTool(query_iam_paths),
        FunctionTool(query_dependency_chain),
        FunctionTool(get_network_exposure),
    ],
    output_key="impact_agent_output",
)

plan_agent = Agent(
    model=_PLANNING_MODEL,
    name="plan_agent",
    description="Generates a structured, step-by-step remediation plan with rollback steps.",
    instruction=PLAN_AGENT_INSTRUCTION,
    tools=[],
    output_key="plan_agent_output",
)

verify_agent = Agent(
    model=_MODEL,
    name="verify_agent",
    description="Confirms remediation success and mutes resolved SCC findings.",
    instruction=VERIFY_AGENT_INSTRUCTION,
    tools=[
        FunctionTool(get_finding_detail),
        FunctionTool(mute_resolved_finding),
    ],
    output_key="verify_agent_output",
)

root_agent = Agent(
    model=_MODEL,
    name="scc_remediation_agent",
    description="Orchestrates triage, impact analysis, remediation planning and verification for GCP SCC findings.",
    instruction=ROOT_AGENT_INSTRUCTION,
    tools=[
        FunctionTool(dispatch_approval_request),
        FunctionTool(create_patch_job),
    ],
    sub_agents=[triage_agent, impact_agent, plan_agent, verify_agent],
)
