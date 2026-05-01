"""
Vertex AI Agent Runtime entrypoint for the SCC Remediation Agent.

agents-cli deploy (deployment_target = agent_runtime) introspects this module
and looks for a module-level `agent_runtime` object.  The object must be an
AdkApp (or subclass) so the Vertex AI SDK can package and deploy it.

Usage:
    uvx google-agents-cli deploy --project YOUR_PROJECT_ID
"""

import logging
import os
from typing import Any

import vertexai
from dotenv import load_dotenv
from google.adk.artifacts import GcsArtifactService, InMemoryArtifactService
from google.cloud import logging as google_cloud_logging
from vertexai.agent_engines.templates.adk import AdkApp

from app.agent import root_agent

load_dotenv()

# Capture location before vertexai.init() may overwrite it
_gemini_location = os.environ.get("GOOGLE_CLOUD_LOCATION")
_logs_bucket = os.environ.get("LOGS_BUCKET_NAME")


class AgentEngineApp(AdkApp):
    """AdkApp subclass that wires Cloud Logging and exposes a feedback endpoint."""

    def set_up(self) -> None:
        vertexai.init()
        super().set_up()
        logging.basicConfig(level=logging.INFO)
        logging_client = google_cloud_logging.Client()
        self._logger = logging_client.logger(__name__)
        if _gemini_location:
            os.environ["GOOGLE_CLOUD_LOCATION"] = _gemini_location

    def register_feedback(self, feedback: dict[str, Any]) -> None:
        """Log user feedback to Cloud Logging."""
        self._logger.log_struct({"feedback": feedback}, severity="INFO")

    def register_operations(self) -> dict[str, list[str]]:
        operations = super().register_operations()
        operations[""] = [*operations.get("", []), "register_feedback"]
        return operations


agent_runtime = AgentEngineApp(
    agent=root_agent,
    artifact_service_builder=lambda: (
        GcsArtifactService(bucket_name=_logs_bucket)
        if _logs_bucket
        else InMemoryArtifactService()
    ),
)
