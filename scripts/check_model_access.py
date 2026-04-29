"""
Preflight check: verify the configured LLM is reachable before launching.

Runs a minimal generate_content call and surfaces billing / auth errors
with actionable messages instead of a long traceback.

Exit codes:
  0 — model reachable
  1 — known, actionable error (billing, auth, quota) — message printed
  2 — unexpected error — message + hint printed
"""
import asyncio
import os
import sys


async def _probe():
    from google import genai
    from google.genai import types

    use_vertex = os.environ.get("GOOGLE_GENAI_USE_VERTEXAI", "True").lower() in ("true", "1")

    if use_vertex:
        client = genai.Client()
    else:
        api_key = os.environ.get("GOOGLE_API_KEY", "")
        if not api_key:
            print("  ✗  GOOGLE_API_KEY is not set.", file=sys.stderr)
            print("     Get a free key at https://aistudio.google.com/apikey", file=sys.stderr)
            sys.exit(1)
        client = genai.Client(api_key=api_key)

    model = os.environ.get("MODEL_ID", "gemini-3-flash-preview")
    await client.aio.models.generate_content(
        model=model,
        contents="reply with the single word: ok",
        config=types.GenerateContentConfig(max_output_tokens=4),
    )


def main():
    use_vertex = os.environ.get("GOOGLE_GENAI_USE_VERTEXAI", "True").lower() in ("true", "1")
    project = os.environ.get("GOOGLE_CLOUD_PROJECT", "")

    label = f"Vertex AI (project: {project})" if use_vertex else "AI Studio"
    print(f"  Checking {label}...", end=" ", flush=True)

    try:
        asyncio.run(_probe())
        print("✓")
        sys.exit(0)

    except Exception as exc:
        print("✗")
        msg = str(exc)

        if "BILLING_DISABLED" in msg or "billing to be enabled" in msg.lower():
            # Extract the billing URL from the error if present
            import re
            url_match = re.search(r"https://console\.developers\.google\.com/billing/enable\?project=\S+", msg)
            billing_url = url_match.group(0).rstrip("'\"") if url_match else \
                f"https://console.cloud.google.com/billing?project={project}"

            print(f"""
  Billing is not enabled on this project.

  Project : {project}
  Enable  : {billing_url}

  Or skip billing entirely — use a free AI Studio key instead:

    ./scripts/local_test.sh --org-id YOUR_ORG_ID --api-key YOUR_KEY --mode A

    Get a key at: https://aistudio.google.com/apikey
""", file=sys.stderr)

        elif "PERMISSION_DENIED" in msg or "403" in msg:
            print(f"""
  Permission denied calling the Gemini API.

  If using Vertex AI, ensure the account has roles/aiplatform.user
  on project '{project}' and the AI Platform API is enabled:

    gcloud services enable aiplatform.googleapis.com --project={project}

  Or use AI Studio (no project permissions needed):

    ./scripts/local_test.sh --org-id YOUR_ORG_ID --api-key YOUR_KEY --mode A
""", file=sys.stderr)

        elif "API_KEY_INVALID" in msg or "invalid" in msg.lower() and "key" in msg.lower():
            print(f"""
  The AI Studio API key is invalid or expired.

  Get a new key at: https://aistudio.google.com/apikey
  Then pass it with: --api-key YOUR_NEW_KEY
""", file=sys.stderr)

        elif "RESOURCE_EXHAUSTED" in msg or "quota" in msg.lower():
            print(f"""
  API quota exceeded. Wait a moment and retry, or:
  - Use a different project
  - Use an AI Studio key (separate quota): --api-key YOUR_KEY
""", file=sys.stderr)

        else:
            print(f"""
  Unexpected error reaching the model API:

    {exc}

  Check that your credentials are set up:
    gcloud auth application-default login
""", file=sys.stderr)
            sys.exit(2)

        sys.exit(1)


if __name__ == "__main__":
    main()
