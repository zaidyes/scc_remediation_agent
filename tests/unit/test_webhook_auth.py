"""
Unit tests for scheduler/webhook_auth.py

Tests use only stdlib / httpx-stubs — no live Google API calls.
All verifiers are tested for:
  - Happy path (valid signature / token)
  - Missing secret / audience env var → 500
  - Missing header → 401
  - Bad signature → 401
"""
import hashlib
import hmac
import json
import os
from unittest.mock import MagicMock, patch

import pytest
from fastapi import HTTPException
from starlette.datastructures import Headers
from starlette.requests import Request
from starlette.types import Scope

from scheduler.webhook_auth import (
    verify_chat_jwt,
    verify_cloud_tasks_token,
    verify_jira_signature,
    verify_pagerduty_signature,
)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _make_request(headers: dict) -> Request:
    """Build a minimal Starlette Request with the given headers."""
    scope: Scope = {
        "type": "http",
        "method": "POST",
        "path": "/webhook/test",
        "query_string": b"",
        "headers": [
            (k.lower().encode(), v.encode()) for k, v in headers.items()
        ],
        "server": ("localhost", 8000),
        "scheme": "https",
    }
    return Request(scope)


def _pd_sig(body: bytes, secret: str) -> str:
    return "v1=" + hmac.new(secret.encode(), body, hashlib.sha256).hexdigest()


def _jira_sig(body: bytes, secret: str) -> str:
    return "sha256=" + hmac.new(secret.encode(), body, hashlib.sha256).hexdigest()


# ---------------------------------------------------------------------------
# verify_chat_jwt
# ---------------------------------------------------------------------------

class TestVerifyChatJwt:

    @pytest.mark.asyncio
    async def test_missing_audience_env_raises_500(self, monkeypatch):
        monkeypatch.delenv("CHAT_WEBHOOK_AUDIENCE", raising=False)
        req = _make_request({"Authorization": "Bearer sometoken"})
        with pytest.raises(HTTPException) as exc:
            await verify_chat_jwt(req)
        assert exc.value.status_code == 500

    @pytest.mark.asyncio
    async def test_missing_auth_header_raises_401(self, monkeypatch):
        monkeypatch.setenv("CHAT_WEBHOOK_AUDIENCE", "https://example.com/webhook/chat")
        req = _make_request({})
        with pytest.raises(HTTPException) as exc:
            await verify_chat_jwt(req)
        assert exc.value.status_code == 401

    @pytest.mark.asyncio
    async def test_invalid_token_raises_401(self, monkeypatch):
        monkeypatch.setenv("CHAT_WEBHOOK_AUDIENCE", "https://example.com/webhook/chat")
        req = _make_request({"Authorization": "Bearer not-a-real-jwt"})
        # id_token.verify_oauth2_token will raise — we don't need to mock Google's JWKS
        with pytest.raises(HTTPException) as exc:
            await verify_chat_jwt(req)
        assert exc.value.status_code == 401

    @pytest.mark.asyncio
    async def test_valid_token_passes(self, monkeypatch):
        monkeypatch.setenv("CHAT_WEBHOOK_AUDIENCE", "https://example.com/webhook/chat")
        req = _make_request({"Authorization": "Bearer valid-token"})
        mock_claims = {"iss": "accounts.google.com", "email": "chat@system.gserviceaccount.com"}
        with patch("scheduler.webhook_auth.id_token.verify_oauth2_token", return_value=mock_claims):
            # Should not raise
            await verify_chat_jwt(req)


# ---------------------------------------------------------------------------
# verify_pagerduty_signature
# ---------------------------------------------------------------------------

class TestVerifyPagerdutySignature:

    @pytest.mark.asyncio
    async def test_missing_secret_env_raises_500(self, monkeypatch):
        monkeypatch.delenv("PAGERDUTY_WEBHOOK_SECRET", raising=False)
        req = _make_request({})
        with pytest.raises(HTTPException) as exc:
            await verify_pagerduty_signature(req, b"{}")
        assert exc.value.status_code == 500

    @pytest.mark.asyncio
    async def test_missing_header_raises_401(self, monkeypatch):
        monkeypatch.setenv("PAGERDUTY_WEBHOOK_SECRET", "secret123")
        req = _make_request({})
        with pytest.raises(HTTPException) as exc:
            await verify_pagerduty_signature(req, b"{}")
        assert exc.value.status_code == 401

    @pytest.mark.asyncio
    async def test_wrong_signature_raises_401(self, monkeypatch):
        monkeypatch.setenv("PAGERDUTY_WEBHOOK_SECRET", "secret123")
        req = _make_request({"X-PagerDuty-Signature": "v1=deadbeef"})
        with pytest.raises(HTTPException) as exc:
            await verify_pagerduty_signature(req, b'{"event": "test"}')
        assert exc.value.status_code == 401

    @pytest.mark.asyncio
    async def test_correct_signature_passes(self, monkeypatch):
        secret = "mysecret"
        body = b'{"messages": []}'
        monkeypatch.setenv("PAGERDUTY_WEBHOOK_SECRET", secret)
        sig = _pd_sig(body, secret)
        req = _make_request({"X-PagerDuty-Signature": sig})
        await verify_pagerduty_signature(req, body)  # No exception

    @pytest.mark.asyncio
    async def test_multiple_signatures_one_valid(self, monkeypatch):
        """Key rotation: header contains old and new signature — one match is enough."""
        secret = "newsecret"
        body = b'{"messages": []}'
        monkeypatch.setenv("PAGERDUTY_WEBHOOK_SECRET", secret)
        valid_sig = _pd_sig(body, secret)
        header_val = f"v1=oldhexvalue, {valid_sig}"
        req = _make_request({"X-PagerDuty-Signature": header_val})
        await verify_pagerduty_signature(req, body)  # No exception

    @pytest.mark.asyncio
    async def test_header_without_v1_prefix_raises_401(self, monkeypatch):
        monkeypatch.setenv("PAGERDUTY_WEBHOOK_SECRET", "secret")
        req = _make_request({"X-PagerDuty-Signature": "sha256=abc"})
        with pytest.raises(HTTPException) as exc:
            await verify_pagerduty_signature(req, b"{}")
        assert exc.value.status_code == 401


# ---------------------------------------------------------------------------
# verify_jira_signature
# ---------------------------------------------------------------------------

class TestVerifyJiraSignature:

    @pytest.mark.asyncio
    async def test_missing_secret_env_raises_500(self, monkeypatch):
        monkeypatch.delenv("JIRA_WEBHOOK_SECRET", raising=False)
        req = _make_request({})
        with pytest.raises(HTTPException) as exc:
            await verify_jira_signature(req, b"{}")
        assert exc.value.status_code == 500

    @pytest.mark.asyncio
    async def test_missing_header_raises_401(self, monkeypatch):
        monkeypatch.setenv("JIRA_WEBHOOK_SECRET", "secret")
        req = _make_request({})
        with pytest.raises(HTTPException) as exc:
            await verify_jira_signature(req, b"{}")
        assert exc.value.status_code == 401

    @pytest.mark.asyncio
    async def test_header_wrong_prefix_raises_401(self, monkeypatch):
        monkeypatch.setenv("JIRA_WEBHOOK_SECRET", "secret")
        req = _make_request({"X-Hub-Signature": "md5=abc"})
        with pytest.raises(HTTPException) as exc:
            await verify_jira_signature(req, b"{}")
        assert exc.value.status_code == 401

    @pytest.mark.asyncio
    async def test_wrong_signature_raises_401(self, monkeypatch):
        monkeypatch.setenv("JIRA_WEBHOOK_SECRET", "secret")
        req = _make_request({"X-Hub-Signature": "sha256=deadbeef"})
        with pytest.raises(HTTPException) as exc:
            await verify_jira_signature(req, b'{"issue": {}}')
        assert exc.value.status_code == 401

    @pytest.mark.asyncio
    async def test_correct_signature_passes(self, monkeypatch):
        secret = "jira_secret"
        body = b'{"issue": {"id": "TEST-1"}}'
        monkeypatch.setenv("JIRA_WEBHOOK_SECRET", secret)
        sig = _jira_sig(body, secret)
        req = _make_request({"X-Hub-Signature": sig})
        await verify_jira_signature(req, body)  # No exception


# ---------------------------------------------------------------------------
# verify_cloud_tasks_token
# ---------------------------------------------------------------------------

class TestVerifyCloudTasksToken:

    @pytest.mark.asyncio
    async def test_missing_audience_env_raises_500(self, monkeypatch):
        monkeypatch.delenv("CLOUD_TASKS_AUDIENCE", raising=False)
        req = _make_request({"Authorization": "Bearer token"})
        with pytest.raises(HTTPException) as exc:
            await verify_cloud_tasks_token(req)
        assert exc.value.status_code == 500

    @pytest.mark.asyncio
    async def test_missing_auth_header_raises_401(self, monkeypatch):
        monkeypatch.setenv("CLOUD_TASKS_AUDIENCE", "https://example.com")
        req = _make_request({})
        with pytest.raises(HTTPException) as exc:
            await verify_cloud_tasks_token(req)
        assert exc.value.status_code == 401

    @pytest.mark.asyncio
    async def test_invalid_token_raises_401(self, monkeypatch):
        monkeypatch.setenv("CLOUD_TASKS_AUDIENCE", "https://example.com")
        req = _make_request({"Authorization": "Bearer badtoken"})
        with pytest.raises(HTTPException) as exc:
            await verify_cloud_tasks_token(req)
        assert exc.value.status_code == 401

    @pytest.mark.asyncio
    async def test_valid_token_no_sa_check_passes(self, monkeypatch):
        monkeypatch.setenv("CLOUD_TASKS_AUDIENCE", "https://example.com/internal/execute")
        monkeypatch.delenv("CLOUD_TASKS_SERVICE_ACCOUNT", raising=False)
        req = _make_request({"Authorization": "Bearer valid-token"})
        mock_claims = {"email": "tasks-runner@project.iam.gserviceaccount.com"}
        with patch("scheduler.webhook_auth.id_token.verify_oauth2_token", return_value=mock_claims):
            await verify_cloud_tasks_token(req)  # No exception

    @pytest.mark.asyncio
    async def test_valid_token_sa_matches_passes(self, monkeypatch):
        sa = "tasks-runner@project.iam.gserviceaccount.com"
        monkeypatch.setenv("CLOUD_TASKS_AUDIENCE", "https://example.com/internal/execute")
        monkeypatch.setenv("CLOUD_TASKS_SERVICE_ACCOUNT", sa)
        req = _make_request({"Authorization": "Bearer valid-token"})
        mock_claims = {"email": sa}
        with patch("scheduler.webhook_auth.id_token.verify_oauth2_token", return_value=mock_claims):
            await verify_cloud_tasks_token(req)  # No exception

    @pytest.mark.asyncio
    async def test_valid_token_sa_mismatch_raises_401(self, monkeypatch):
        monkeypatch.setenv("CLOUD_TASKS_AUDIENCE", "https://example.com/internal/execute")
        monkeypatch.setenv("CLOUD_TASKS_SERVICE_ACCOUNT", "expected-sa@project.iam.gserviceaccount.com")
        req = _make_request({"Authorization": "Bearer valid-token"})
        mock_claims = {"email": "other-sa@project.iam.gserviceaccount.com"}
        with patch("scheduler.webhook_auth.id_token.verify_oauth2_token", return_value=mock_claims):
            with pytest.raises(HTTPException) as exc:
                await verify_cloud_tasks_token(req)
        assert exc.value.status_code == 401
