# ADK Core Imports (Assumed standard for Agent Garden ADK)
try:
    from adk import Agent
    from adk.models import Gemini
    import adk.types as types
except ImportError:
    # Fallback/Mock for local testing without the framework
    class Agent:
        def __init__(self, **kwargs): pass
    class Gemini:
        def __init__(self, **kwargs): pass
    class types:
        class HttpRetryOptions:
            def __init__(self, **kwargs): pass

from app.tools.scc_tools import get_finding_detail, mute_resolved_finding
from app.tools.graph_tools import query_blast_radius, query_iam_paths, check_dormancy
from app.tools.network_tools import get_network_exposure
from app.tools.osconfig_tools import create_patch_job
from app.tools.approval_tools import dispatch_approval_request

INSTRUCTION = """
You are the SCC Remediation Agent. Your job is to autonomously triage, analyze, and remediate security findings from Google Cloud Security Command Center (SCC).

Workflow:
1. When a finding is presented, use `query_blast_radius`, `query_iam_paths`, and `get_network_exposure` to determine the blast radius and risk.
2. Check `check_dormancy` to see if the asset is active or dormant.
3. If the risk is high or the asset is critical, generate a remediation plan and use `dispatch_approval_request` to seek human approval before taking action.
4. If approved (or if it's a safe auto-remediate task), execute the remediation using tools like `create_patch_job`.
5. Finally, verify the fix and use `mute_resolved_finding`.

Always provide clear, JSON-structured plans when requesting approvals, including your reasoning on the blast radius.
"""

root_agent = Agent(
    name="scc_remediation_agent",
    model=Gemini(
        model="gemini-3-flash-preview",
        retry_options=types.HttpRetryOptions(attempts=3),
    ),
    instruction=INSTRUCTION,
    tools=[
        get_finding_detail,
        query_blast_radius,
        query_iam_paths,
        check_dormancy,
        get_network_exposure,
        create_patch_job,
        dispatch_approval_request,
        mute_resolved_finding
    ],
)
