"""Unit tests for exposed sensitive endpoints and metadata scanning."""

import pytest
import httpx
from apiguard.core.endpoints import EndpointScanner
from apiguard.models.enums import Severity


@pytest.mark.asyncio
async def test_exposed_env_file_critical():
    def handler(request: httpx.Request) -> httpx.Response:
        if request.url.path == "/.env":
            return httpx.Response(
                200,
                headers={"content-type": "text/plain"},
                text="DATABASE_URL=postgres://user:password@localhost:5432/prod\nSECRET_KEY=supersecret",
            )
        return httpx.Response(404)

    transport = httpx.MockTransport(handler)
    async with httpx.AsyncClient(transport=transport) as client:
        findings = await EndpointScanner.scan(client, "https://api.example.com")

    env_finding = next(f for f in findings if f.path == "/.env")
    assert env_finding.is_exposed
    assert env_finding.severity == Severity.CRITICAL
    assert env_finding.status_code == 200


@pytest.mark.asyncio
async def test_spa_fallback_false_positive_rejected():
    def handler(request: httpx.Request) -> httpx.Response:
        # SPA returning HTML for all paths
        return httpx.Response(
            200,
            headers={"content-type": "text/html; charset=utf-8"},
            text="<!DOCTYPE html><html><head><title>App</title></head><body><div id='root'></div></body></html>",
        )

    transport = httpx.MockTransport(handler)
    async with httpx.AsyncClient(transport=transport) as client:
        findings = await EndpointScanner.scan(client, "https://api.example.com")

    env_finding = next(f for f in findings if f.path == "/.env")
    assert not env_finding.is_exposed
    assert env_finding.severity == Severity.PASS


@pytest.mark.asyncio
async def test_exposed_git_head_critical():
    def handler(request: httpx.Request) -> httpx.Response:
        if request.url.path == "/.git/HEAD":
            return httpx.Response(
                200,
                headers={"content-type": "text/plain"},
                text="ref: refs/heads/main\n",
            )
        return httpx.Response(404)

    transport = httpx.MockTransport(handler)
    async with httpx.AsyncClient(transport=transport) as client:
        findings = await EndpointScanner.scan(client, "https://api.example.com")

    git_finding = next(f for f in findings if f.path == "/.git/HEAD")
    assert git_finding.is_exposed
    assert git_finding.severity == Severity.CRITICAL


@pytest.mark.asyncio
async def test_exposed_openapi_schema():
    def handler(request: httpx.Request) -> httpx.Response:
        if request.url.path == "/openapi.json":
            return httpx.Response(
                200,
                headers={"content-type": "application/json"},
                text='{"openapi": "3.0.0", "info": {"title": "Test API"}, "paths": {}}',
            )
        return httpx.Response(404)

    transport = httpx.MockTransport(handler)
    async with httpx.AsyncClient(transport=transport) as client:
        findings = await EndpointScanner.scan(client, "https://api.example.com")

    spec_finding = next(f for f in findings if f.path == "/openapi.json")
    assert spec_finding.is_exposed
    assert spec_finding.severity == Severity.LOW


@pytest.mark.asyncio
async def test_custom_endpoint_probing():
    def handler(request: httpx.Request) -> httpx.Response:
        if request.url.path == "/custom-diagnostic":
            return httpx.Response(200, text="internal debug output")
        return httpx.Response(404)

    transport = httpx.MockTransport(handler)
    async with httpx.AsyncClient(transport=transport) as client:
        findings = await EndpointScanner.scan(
            client,
            "https://api.example.com",
            custom_paths=["/custom-diagnostic"],
        )

    custom_finding = next((f for f in findings if f.path == "/custom-diagnostic"), None)
    assert custom_finding is not None
    assert custom_finding.is_exposed
