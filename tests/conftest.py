"""Shared pytest fixtures, mock factories, and sample JWT tokens."""

import base64
import hashlib
import hmac
import json
import time
from typing import Any
import pytest


def make_jwt(header: dict[str, Any], payload: dict[str, Any], secret: str = "secret") -> str:
    """Helper to construct synthetic JWTs for testing."""
    h_b64 = base64.urlsafe_b64encode(json.dumps(header).encode()).decode().rstrip("=")
    p_b64 = base64.urlsafe_b64encode(json.dumps(payload).encode()).decode().rstrip("=")
    signing_input = f"{h_b64}.{p_b64}"

    alg = header.get("alg", "HS256")
    if alg.lower() == "none":
        return f"{signing_input}."

    sig = base64.urlsafe_b64encode(
        hmac.new(secret.encode(), signing_input.encode(), hashlib.sha256).digest()
    ).decode().rstrip("=")
    return f"{signing_input}.{sig}"


@pytest.fixture
def sample_valid_jwt() -> str:
    header = {"alg": "HS256", "typ": "JWT"}
    payload = {
        "sub": "user_12345",
        "name": "Alice Auditor",
        "role": "compliance_analyst",
        "iat": int(time.time()),
        "exp": int(time.time()) + 3600,
    }
    return make_jwt(header, payload, secret="unbreakable_random_vault_secret_99881122")


@pytest.fixture
def sample_expired_jwt() -> str:
    header = {"alg": "HS256", "typ": "JWT"}
    payload = {
        "sub": "user_expired",
        "iat": int(time.time()) - 7200,
        "exp": int(time.time()) - 3600,
    }
    return make_jwt(header, payload, secret="any_secret")


@pytest.fixture
def sample_none_alg_jwt() -> str:
    header = {"alg": "none", "typ": "JWT"}
    payload = {
        "sub": "admin_bypass",
        "role": "superadmin",
        "exp": int(time.time()) + 3600,
    }
    return make_jwt(header, payload)


@pytest.fixture
def sample_weak_secret_jwt() -> str:
    header = {"alg": "HS256", "typ": "JWT"}
    payload = {
        "sub": "service_account",
        "scope": "api:admin",
        "exp": int(time.time()) + 1800,
    }
    return make_jwt(header, payload, secret="password123")


@pytest.fixture
def sample_secure_headers() -> dict[str, str]:
    return {
        "content-security-policy": "default-src 'self'; frame-ancestors 'none'",
        "strict-transport-security": "max-age=31536000; includeSubDomains; preload",
        "x-content-type-options": "nosniff",
        "x-frame-options": "DENY",
        "referrer-policy": "strict-origin-when-cross-origin",
        "permissions-policy": "camera=(), microphone=(), geolocation=()",
    }


@pytest.fixture
def sample_insecure_headers() -> dict[str, str]:
    return {
        "server": "Apache/2.4.41 (Ubuntu)",
        "x-powered-by": "PHP/7.4.3",
        "referrer-policy": "unsafe-url",
        "content-security-policy": "default-src *; script-src 'unsafe-inline' 'unsafe-eval'",
    }
