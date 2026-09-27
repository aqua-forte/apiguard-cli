"""Scanner for exposed sensitive files, metadata, and diagnostic endpoints."""

import asyncio
from typing import NamedTuple
from urllib.parse import urljoin
import httpx

from apiguard.models.audit import EndpointFinding
from apiguard.models.enums import Severity


class TargetEndpoint(NamedTuple):
    path: str
    expected_severity: Severity
    description: str
    remediation: str


class EndpointScanner:
    """Detects public exposure of sensitive files, diagnostic endpoints, and metadata."""

    DEFAULT_PROBES: list[TargetEndpoint] = [
        TargetEndpoint(
            path="/.env",
            expected_severity=Severity.CRITICAL,
            description="Exposed environment configuration file. Leaks database credentials and API secrets.",
            remediation="Block access to dotfiles (.env) in web server / reverse proxy configuration immediately.",
        ),
        TargetEndpoint(
            path="/.git/HEAD",
            expected_severity=Severity.CRITICAL,
            description="Exposed Git repository metadata. Allows full reconstruction of application source code.",
            remediation="Deny public HTTP access to all /.git/ directories on production servers.",
        ),
        TargetEndpoint(
            path="/actuator/env",
            expected_severity=Severity.CRITICAL,
            description="Exposed Spring Boot Actuator environment endpoint. Exposes runtime configs and passwords.",
            remediation="Secure or disable Spring Actuator endpoints via management.endpoints.web.exposure.exclude.",
        ),
        TargetEndpoint(
            path="/actuator/health",
            expected_severity=Severity.LOW,
            description="Exposed Spring Boot Actuator health endpoint. Discloses internal component statuses.",
            remediation="Restrict Actuator health details to authenticated monitoring services.",
        ),
        TargetEndpoint(
            path="/metrics",
            expected_severity=Severity.MEDIUM,
            description="Exposed Prometheus/OpenTelemetry metrics endpoint. Leaks internal telemetry and infrastructure data.",
            remediation="Bind metrics port to internal loopback or require mutual TLS / authentication.",
        ),
        TargetEndpoint(
            path="/openapi.json",
            expected_severity=Severity.LOW,
            description="Publicly accessible OpenAPI v3 specification. Discloses internal schema and routes.",
            remediation="Restrict OpenAPI documentation to authenticated internal developer portals if private.",
        ),
        TargetEndpoint(
            path="/swagger.json",
            expected_severity=Severity.LOW,
            description="Publicly accessible Swagger v2 specification. Discloses full API surface area.",
            remediation="Require authentication to access Swagger schema specifications.",
        ),
        TargetEndpoint(
            path="/swagger-ui.html",
            expected_severity=Severity.INFO,
            description="Interactive Swagger UI console accessible publicly.",
            remediation="Disable Swagger UI in production environments.",
        ),
        TargetEndpoint(
            path="/healthz",
            expected_severity=Severity.INFO,
            description="Kubernetes/container health probe endpoint reachable publicly.",
            remediation="Ensure health check endpoint does not leak detailed stack traces on failures.",
        ),
    ]

    @classmethod
    async def scan(
        cls,
        client: httpx.AsyncClient,
        base_url: str,
        custom_paths: list[str] | None = None,
        concurrency: int = 5,
    ) -> list[EndpointFinding]:
        """Asynchronously probes endpoints with concurrency control and false-positive filtering."""
        probes = list(cls.DEFAULT_PROBES)
        if custom_paths:
            for cp in custom_paths:
                clean_p = "/" + cp.lstrip("/")
                if not any(p.path == clean_p for p in probes):
                    probes.append(
                        TargetEndpoint(
                            path=clean_p,
                            expected_severity=Severity.MEDIUM,
                            description=f"Custom probed endpoint: {clean_p}",
                            remediation="Verify whether this route should be exposed publicly.",
                        )
                    )

        semaphore = asyncio.Semaphore(concurrency)

        async def _check_endpoint(target: TargetEndpoint) -> EndpointFinding:
            async with semaphore:
                target_url = urljoin(base_url, target.path)
                try:
                    resp = await client.get(target_url)
                    return cls._evaluate_response(target, resp)
                except Exception as exc:
                    return EndpointFinding(
                        path=target.path,
                        status_code=None,
                        is_exposed=False,
                        content_type=None,
                        severity=Severity.INFO,
                        risk_description=f"Endpoint unreachable: {str(exc)}",
                        sample_snippet=None,
                        remediation=target.remediation,
                    )

        tasks = [_check_endpoint(p) for p in probes]
        results = await asyncio.gather(*tasks)
        return list(results)

    @classmethod
    def _evaluate_response(cls, target: TargetEndpoint, resp: httpx.Response) -> EndpointFinding:
        status_code = resp.status_code
        content_type = resp.headers.get("content-type", "").lower()
        snippet = resp.text[:200].strip() if resp.text else None

        # Treat 200, 204, 206 as potential exposure, but apply smart content heuristics
        if status_code in (200, 206):
            # False positive prevention: Single Page Apps returning 200 with HTML for 404s
            is_html = "text/html" in content_type

            if target.path == "/.env":
                # Valid .env must contain key=value syntax and not HTML tags
                if is_html or "<html" in (resp.text[:500].lower()) or "<!doctype" in (resp.text[:500].lower()):
                    return EndpointFinding(
                        path=target.path,
                        status_code=status_code,
                        is_exposed=False,
                        content_type=content_type,
                        severity=Severity.PASS,
                        risk_description="Returned HTML (likely SPA fallback, not genuine .env file).",
                        sample_snippet=None,
                        remediation=target.remediation,
                    )
                if "=" in resp.text[:500]:
                    return EndpointFinding(
                        path=target.path,
                        status_code=status_code,
                        is_exposed=True,
                        content_type=content_type,
                        severity=Severity.CRITICAL,
                        risk_description=target.description,
                        sample_snippet=snippet,
                        remediation=target.remediation,
                    )

            elif target.path == "/.git/HEAD":
                if "ref: refs/" in resp.text or (len(resp.text.strip()) == 40 and all(c in "0123456789abcdef" for c in resp.text.strip())):
                    return EndpointFinding(
                        path=target.path,
                        status_code=status_code,
                        is_exposed=True,
                        content_type=content_type,
                        severity=Severity.CRITICAL,
                        risk_description=target.description,
                        sample_snippet=snippet,
                        remediation=target.remediation,
                    )
                else:
                    return EndpointFinding(
                        path=target.path,
                        status_code=status_code,
                        is_exposed=False,
                        content_type=content_type,
                        severity=Severity.PASS,
                        risk_description="Returned non-git content.",
                        sample_snippet=None,
                        remediation=target.remediation,
                    )

            elif target.path in ("/openapi.json", "/swagger.json"):
                if is_html:
                    return EndpointFinding(
                        path=target.path,
                        status_code=status_code,
                        is_exposed=False,
                        content_type=content_type,
                        severity=Severity.PASS,
                        risk_description="Returned HTML instead of API specification schema.",
                        sample_snippet=None,
                        remediation=target.remediation,
                    )
                lower_text = resp.text[:1000].lower()
                if "openapi" in lower_text or "swagger" in lower_text or "paths" in lower_text:
                    return EndpointFinding(
                        path=target.path,
                        status_code=status_code,
                        is_exposed=True,
                        content_type=content_type,
                        severity=target.expected_severity,
                        risk_description=target.description,
                        sample_snippet=snippet,
                        remediation=target.remediation,
                    )

            elif target.path == "/metrics":
                if is_html:
                    return EndpointFinding(
                        path=target.path,
                        status_code=status_code,
                        is_exposed=False,
                        content_type=content_type,
                        severity=Severity.PASS,
                        risk_description="Returned HTML instead of Prometheus metrics format.",
                        sample_snippet=None,
                        remediation=target.remediation,
                    )
                if "# help" in resp.text.lower() or "# type" in resp.text.lower() or "jvm_" in resp.text or "http_" in resp.text:
                    return EndpointFinding(
                        path=target.path,
                        status_code=status_code,
                        is_exposed=True,
                        content_type=content_type,
                        severity=target.expected_severity,
                        risk_description=target.description,
                        sample_snippet=snippet,
                        remediation=target.remediation,
                    )

            # Default genuine 200 exposure
            return EndpointFinding(
                path=target.path,
                status_code=status_code,
                is_exposed=True,
                content_type=content_type,
                severity=target.expected_severity,
                risk_description=target.description,
                sample_snippet=snippet,
                remediation=target.remediation,
            )

        elif status_code in (401, 403):
            return EndpointFinding(
                path=target.path,
                status_code=status_code,
                is_exposed=False,
                content_type=content_type,
                severity=Severity.PASS,
                risk_description=f"Endpoint exists but is correctly protected with HTTP {status_code}.",
                sample_snippet=None,
                remediation=target.remediation,
            )

        # 404 Not Found or other non-exposed codes
        return EndpointFinding(
            path=target.path,
            status_code=status_code,
            is_exposed=False,
            content_type=content_type,
            severity=Severity.PASS,
            risk_description="Endpoint returned non-exposed status.",
            sample_snippet=None,
            remediation=target.remediation,
        )
