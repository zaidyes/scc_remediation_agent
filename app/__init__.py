import os

os.environ.setdefault("GOOGLE_CLOUD_LOCATION", "global")
os.environ.setdefault("GOOGLE_GENAI_USE_VERTEXAI", "True")

# Only resolve the ADC project when Vertex AI is actually in use.
# If GOOGLE_GENAI_USE_VERTEXAI=False (AI Studio key), probing google.auth.default()
# would pick up whatever project gcloud last touched — which may have billing
# disabled — and that project would end up being used for API calls.
_use_vertex = os.environ.get("GOOGLE_GENAI_USE_VERTEXAI", "True").lower() in ("true", "1")
if _use_vertex and not os.environ.get("GOOGLE_CLOUD_PROJECT"):
    try:
        import google.auth
        _, _project_id = google.auth.default()
        if _project_id:
            os.environ["GOOGLE_CLOUD_PROJECT"] = _project_id
    except Exception:
        pass

from .agent import root_agent  # noqa: E402, F401
