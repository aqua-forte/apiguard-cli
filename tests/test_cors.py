"""Unit tests for Cross-Origin Resource Sharing (CORS) auditing logic."""

import pytest
import httpx
from apiguard.core.cors import CorsAuditor
from apiguard.models.enums import AuditStatus, Severity


@pytest.mark.asyncio
async def test_cors_no_acao_safe():
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, headers={})

    transport = httpx.MockTransport(handler)
    async with httpx.AsyncClient(transport=transport) as client:
        findings = await CorsAuditor.audit(client, "https://api.example.com")

    # All probes should result in PASSED since no ACAO was reflected
    get_findings = [f for f in findings if f.test_origin != "OPTIONS Preflight"]
    for f in get_findings:
        assert f.status == AuditStatus.PASSED
        assert f.severity == Severity.PASS
        assert not f.is_origin_reflected


@pytest.mark.asyncio
async def test_cors_reflected_origin_with_credentials_critical():
    def handler(request: httpx.Request) -> httpx.Response:
        origin = request.headers.get("Origin", "")
        return httpx.Response(
            200,
            headers={
                "Access-Control-Allow-Origin": origin,
                "Access-Control-Allow-Credentials": "true",
            },
        )

    transport = httpx.MockTransport(handler)
    async with httpx.AsyncClient(transport=transport) as client:
        findings = await CorsAuditor.audit(client, "https://api.example.com")

    critical_finding = next(f for f in findings if f.test_origin == "https://evil.example.com")
    assert critical_finding.severity == Severity.CRITICAL
    assert critical_finding.status == AuditStatus.FAILED
    assert critical_finding.is_origin_reflected
    assert "CRITICAL CORS Misconfiguration" in critical_finding.description


@pytest.mark.asyncio
async def test_cors_wildcard_with_credentials():
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(
            200,
            headers={
                "Access-Control-Allow-Origin": "*",
                "Access-Control-Allow-Credentials": "true",
            },
        )

    transport = httpx.MockTransport(handler)
    async with httpx.AsyncClient(transport=transport) as client:
        findings = await CorsAuditor.audit(client, "https://api.example.com")

    finding = next(f for f in findings if f.test_origin == "https://evil.example.com")
    assert finding.severity == Severity.HIGH
    assert finding.is_wildcard_with_credentials


@pytest.mark.asyncio
async def test_cors_preflight_wildcard_method():
    def handler(request: httpx.Request) -> httpx.Response:
        if request.method == "OPTIONS":
            return httpx.Response(
                200,
                headers={
                    "Access-Control-Allow-Origin": "*",
                    "Access-Control-Allow-Methods": "*",
                },
            )
        return httpx.Response(200)

    transport = httpx.MockTransport(handler)
    async with httpx.AsyncClient(transport=transport) as client:
        findings = await CorsAuditor.audit(client, "https://api.example.com")

    preflight = next(f for f in findings if f.test_origin == "OPTIONS Preflight")
    assert preflight.severity == Severity.MEDIUM
    assert "wildcard HTTP methods" in preflight.description
