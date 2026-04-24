import json
import os
import uuid

from google import genai
from google.genai import types

from config.schema import RemediationMode

PLAN_PROMPT_TEMPLATE = """
You are a GCP security remediation specialist. Generate a detailed remediation plan.

## Finding
{finding_json}

## Asset context
{impact_json}

## Dormancy
{dormancy_json}

## SCC remediation guidance
{remediation_text}

## Customer config
Enabled remediation modes: {enabled_modes}
Dry run: {dry_run}

## Instructions
Generate a JSON remediation plan with the following structure:
{{
  "plan_id": "<uuid>",
  "finding_id": "<finding_id>",
  "asset_name": "<asset_name>",
  "remediation_type": "OS_PATCH | MISCONFIGURATION | IAM | FIREWALL",
  "summary": "<one sentence>",
  "risk_assessment": "<2-3 sentences on blast radius and change risk>",
  "steps": [
    {{
      "order": 1,
      "action": "<description>",
      "api_call": "<gcloud command or API>",
      "expected_outcome": "<what happens>",
      "verification": "<how to confirm success>"
    }}
  ],
  "rollback_steps": [
    {{
      "order": 1,
      "action": "<rollback action>",
      "api_call": "<gcloud command or API>"
    }}
  ],
  "estimated_downtime_minutes": 0,
  "requires_reboot": false,
  "confidence": "HIGH | MEDIUM | LOW",
  "change_window_required": true
}}

Return only valid JSON. No preamble or explanation.
"""

_FINDING_CLASS_TO_MODE = {
    "VULNERABILITY": "OS_PATCH",
    "MISCONFIGURATION": "MISCONFIGURATION",
    "SCC_ERROR": None,
    "OBSERVATION": None,
}


class PlanAgent:
    def __init__(self, config):
        self.config = config

    async def generate(self, finding: dict, impact: dict, dormancy: dict) -> dict | None:
        enabled_modes = [m.value for m in self.config.execution.enabled_modes]

        finding_class = finding.get("finding_class", "")
        if not _has_applicable_mode(finding_class, enabled_modes):
            return None

        prompt = PLAN_PROMPT_TEMPLATE.format(
            finding_json=json.dumps(finding, indent=2, default=str),
            impact_json=json.dumps(impact, indent=2),
            dormancy_json=json.dumps(dormancy, indent=2),
            remediation_text=finding.get("remediation_text", "No guidance available."),
            enabled_modes=", ".join(enabled_modes),
            dry_run=self.config.dry_run,
        )

        client = genai.Client()
        response = await client.aio.models.generate_content(
            model=os.getenv("PLANNING_MODEL_ID", "gemini-3.1-pro-preview"),
            contents=prompt,
            config=types.GenerateContentConfig(response_mime_type="application/json"),
        )

        raw = response.text.strip()
        plan = json.loads(raw)
        plan["plan_id"] = plan.get("plan_id") or str(uuid.uuid4())
        plan["dry_run"] = self.config.dry_run
        return plan


def _has_applicable_mode(finding_class: str, enabled_modes: list[str]) -> bool:
    required = _FINDING_CLASS_TO_MODE.get(finding_class)
    return required is not None and required in enabled_modes
