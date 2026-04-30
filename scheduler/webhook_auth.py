"""
webhook_auth.py — Signature / token verification for all inbound webhook sources.

Each verifier raises HTTPException(401) on failure so FastAPI returns the
correct status code without leaking internal detail to the caller.

Four sources are covered:

  verify_chat_jwt(request)
      Google Chat interactive card callbacks carry a Google-signed JWT in the
      Authorization: Bearer header.  Verified against Google's public JWKS.
      Env: CHAT_WEBHOOK_AUDIENCE (the URL of the /webhook/chat endpoint)

  verify_pagerduty_signature(request, body)
      PagerDuty v3 webhooks include X-PagerDuty-Signature: v1=<hex>.
      Env: PAGERDUTY_WEBHOOK_SECRET

  verify_jira_signature(request, body)
      Jira webhooks include X-Hub-Signature: sha256=<hex>.
      Env: JIRA_WEBHOOK_SECRET

  verify_cloud_tasks_token(request)
      Cloud Tasks attaches an OIDC token when configured with a service account.
      Verified against Google's public JWKS; optionally checks the SA email.
      Env: CLOUD_TASKS_AUDIENCE, CLOUD_TASKS_SERVICE_ACCOUNT (optional)

All verifiers follow the same failure contract:
  - Secret/audience env var missing          → 500 (misconfiguration)
  - Signature header missing or malformed   → 401
  - Signature / token does not verify       → 401
"""
import hashlib
import hmac
import os

from fastapi import HTTPException, Request
from google.auth.transport import requests as google_requests
from google.oauth2 import id_token


# ---------------------------------------------------------------------------
# Google Chat — JWT bearer token verification
# ---------------------------------------------------------------------------
# Google Chat signs every interactive card callback with a service-account JWT.
# The token's `aud` claim must match the receiving endpoint URL exactly.
#
# Reference: https://developers.google.com/chat/how-tos/authorize-chat-app

_CHAT_AUDIENCE_ENV = "CHAT_WEBHOOK_AUDIENCE"


async def verify_chat_jwt(request: Request) -> None:
    """Raises HTTPException if the request is not from Google Chat."""
    audience = os.environ.get(_CHAT_AUDIENCE_ENV, "")
    if not audience:
        raise HTTPException(
            status_code=500,
            detail=f"{_CHAT_AUDIENCE_ENV} env var not configured",
        )

    auth_header = request.headers.get("Authorization", "")
    if not auth_header.startswith("Bearer "):
        raise HTTPException(status_code=401, detail="Missing Chat bearer token")

    token = auth_header[len("Bearer "):]
    try:
        id_token.verify_oauth2_token(
            token,
            google_requests.Request(),
            audience=audience,
        )
    except Exception as exc:
        raise HTTPException(
            status_code=401,
            detail=f"Invalid Chat token: {exc}",
        ) from exc


# ---------------------------------------------------------------------------
# PagerDuty — HMAC-SHA256 signature verification
# ---------------------------------------------------------------------------
# PagerDuty v3 webhooks include:
#   X-PagerDuty-Signature: v1=<hex>[,v1=<hex>]
# Multiple signatures are allowed (key rotation).
#
# Reference: https://developer.pagerduty.com/docs/db0fa8c8984fc-verifying-signatures

_PD_SECRET_ENV = "PAGERDUTY_WEBHOOK_SECRET"
_PD_HEADER = "X-PagerDuty-Signature"


async def verify_pagerduty_signature(request: Request, body: bytes) -> None:
    """Raises HTTPException if the PagerDuty HMAC is invalid."""
    secret = os.environ.get(_PD_SECRET_ENV, "")
    if not secret:
        raise HTTPException(
            status_code=500,
            detail=f"{_PD_SECRET_ENV} env var not configured",
        )

    header_val = request.headers.get(_PD_HEADER, "")
    signatures = [
        s.strip()[len("v1="):]
        for s in header_val.split(",")
        if s.strip().startswith("v1=")
    ]
    if not signatures:
        raise HTTPException(
            status_code=401,
            detail=f"Missing or malformed {_PD_HEADER} header",
        )

    expected = hmac.new(secret.encode(), body, hashlib.sha256).hexdigest()
    for sig in signatures:
        if hmac.compare_digest(expected, sig):
            return  # At least one signature matched

    raise HTTPException(status_code=401, detail="PagerDuty signature mismatch")


# ---------------------------------------------------------------------------
# Jira — HMAC-SHA256 signature verification
# ---------------------------------------------------------------------------
# Jira webhooks include:
#   X-Hub-Signature: sha256=<hex>
#
# Reference: https://developer.atlassian.com/server/jira/platform/webhooks/

_JIRA_SECRET_ENV = "JIRA_WEBHOOK_SECRET"
_JIRA_HEADER = "X-Hub-Signature"


async def verify_jira_signature(request: Request, body: bytes) -> None:
    """Raises HTTPException if the Jira HMAC is invalid."""
    secret = os.environ.get(_JIRA_SECRET_ENV, "")
    if not secret:
        raise HTTPException(
            status_code=500,
            detail=f"{_JIRA_SECRET_ENV} env var not configured",
        )

    header_val = request.headers.get(_JIRA_HEADER, "")
    if not header_val.startswith("sha256="):
        raise HTTPException(
            status_code=401,
            detail=f"Missing or malformed {_JIRA_HEADER} header",
        )

    candidate = header_val[len("sha256="):]
    expected = hmac.new(secret.encode(), body, hashlib.sha256).hexdigest()
    if not hmac.compare_digest(expected, candidate):
        raise HTTPException(status_code=401, detail="Jira signature mismatch")


# ---------------------------------------------------------------------------
# Generic Google OIDC token verification (reusable)
# ---------------------------------------------------------------------------

async def verify_google_oidc_token(request: Request, audience_env: str) -> dict:
    """
    Verifies a Google-signed OIDC Bearer token and returns the claims dict.
    The token audience must match the value of the given env var.

    Raises HTTPException(500) if the audience env var is not set.
    Raises HTTPException(401) if the token is missing or invalid.
    """
    audience = os.environ.get(audience_env, "")
    if not audience:
        raise HTTPException(
            status_code=500,
            detail=f"{audience_env} env var not configured",
        )

    auth_header = request.headers.get("Authorization", "")
    if not auth_header.startswith("Bearer "):
        raise HTTPException(status_code=401, detail="Missing Bearer token")

    token = auth_header[len("Bearer "):]
    try:
        claims = id_token.verify_oauth2_token(
            token,
            google_requests.Request(),
            audience=audience,
        )
    except Exception as exc:
        raise HTTPException(
            status_code=401,
            detail=f"Invalid token: {exc}",
        ) from exc

    return claims


# ---------------------------------------------------------------------------
# Cloud Tasks — OIDC token verification
# ---------------------------------------------------------------------------
# When a Cloud Tasks HTTP target is configured with an OIDC service account,
# Cloud Tasks attaches:
#   Authorization: Bearer <OIDC-signed JWT>
# The token's `aud` claim is set to the target URL by default, or to the
# explicit audience configured on the task.
#
# We verify the token and optionally assert the service account email matches
# CLOUD_TASKS_SERVICE_ACCOUNT to prevent tokens from other SAs being accepted.
#
# Reference: https://cloud.google.com/tasks/docs/creating-http-target-tasks#token

_TASKS_AUDIENCE_ENV = "CLOUD_TASKS_AUDIENCE"
_TASKS_SA_ENV = "CLOUD_TASKS_SERVICE_ACCOUNT"


async def verify_cloud_tasks_token(request: Request) -> None:
    """Raises HTTPException if the request is not from the authorised Cloud Tasks SA."""
    audience = os.environ.get(_TASKS_AUDIENCE_ENV, "")
    if not audience:
        raise HTTPException(
            status_code=500,
            detail=f"{_TASKS_AUDIENCE_ENV} env var not configured",
        )

    auth_header = request.headers.get("Authorization", "")
    if not auth_header.startswith("Bearer "):
        raise HTTPException(status_code=401, detail="Missing Cloud Tasks OIDC token")

    token = auth_header[len("Bearer "):]
    try:
        claims = id_token.verify_oauth2_token(
            token,
            google_requests.Request(),
            audience=audience,
        )
    except Exception as exc:
        raise HTTPException(
            status_code=401,
            detail=f"Invalid Cloud Tasks OIDC token: {exc}",
        ) from exc

    expected_sa = os.environ.get(_TASKS_SA_ENV, "")
    if expected_sa and claims.get("email") != expected_sa:
        raise HTTPException(
            status_code=401,
            detail=f"Unexpected Cloud Tasks service account: {claims.get('email')}",
        )
