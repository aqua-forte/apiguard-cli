"""Cross-Origin Resource Sharing (CORS) policy and misconfiguration auditor."""

from typing import Optional
import httpx

from apiguard.models.audit import CorsFinding
from apiguard.models.enums import AuditStatus, Severity


class CorsAuditor:
    """Evaluates server CORS responses against RFC 6454 and OWASP recommendations."""

    TEST_ORIGINS = [
        "https://evil.example.com",
        "https://untrusted-site.org",
        "null",
    ]

    @classmethod
    async def audit(cls, client: httpx.AsyncClient, url: str) -> list[CorsFinding]:
        """Probes endpoint with multiple Origin headers and Preflight OPTIONS requests."""
        findings: list[CorsFinding] = []

        for origin in cls.TEST_ORIGINS:
            try:
                response = await client.get(url, headers={"Origin": origin})
                finding = cls._analyze_cors_response(origin, response.headers)
                findings.append(finding)
            except Exception as exc:
                findings.append(
                    CorsFinding(
                        test_origin=origin,
                        status=AuditStatus.SKIPPED,
                        severity=Severity.INFO,
                        description=f"Could not complete GET CORS probe for origin '{origin}': {str(exc)}",
                        remediation="Verify network connectivity and URL availability.",
                    )
                )

        # Preflight OPTIONS probe
        try:
            options_resp = await client.options(
                url,
                headers={
                    "Origin": "https://evil.example.com",
                    "Access-Control-Request-Method": "PUT",
                    "Access-Control-Request-Headers": "X-Custom-Auth, Authorization",
                },
            )
            preflight_finding = cls._analyze_preflight(options_resp.headers)
            findings.append(preflight_finding)
        except Exception as exc:
            findings.append(
                CorsFinding(
                    test_origin="OPTIONS Preflight",
                    status=AuditStatus.SKIPPED,
                    severity=Severity.INFO,
                    description=f"Preflight OPTIONS probe failed: {str(exc)}",
                    remediation="Verify if server supports or handles OPTIONS HTTP requests.",
                )
            )

        return findings

    @classmethod
    def _analyze_cors_response(cls, test_origin: str, headers: httpx.Headers) -> CorsFinding:
        acao = headers.get("access-control-allow-origin")
        acac = headers.get("access-control-allow-credentials")

        allow_credentials = (acac.lower() == "true") if acac else False
        is_wildcard = (acao == "*")
        is_reflected = (acao is not None and acao.lower() == test_origin.lower())

        if not acao:
            return CorsFinding(
                test_origin=test_origin,
                allow_origin=None,
                allow_credentials=acac,
                is_origin_reflected=False,
                is_wildcard_with_credentials=False,
                is_wildcard=False,
                status=AuditStatus.PASSED,
                severity=Severity.PASS,
                description=f"Server did not return ACAO header for untrusted origin '{test_origin}'. Strict SOP maintained.",
                remediation="Keep default same-origin protection intact.",
            )

        # Critical: Arbitrary Origin reflection with credentials
        if is_reflected and allow_credentials:
            return CorsFinding(
                test_origin=test_origin,
                allow_origin=acao,
                allow_credentials=acac,
                is_origin_reflected=True,
                is_wildcard_with_credentials=False,
                is_wildcard=False,
                status=AuditStatus.FAILED,
                severity=Severity.CRITICAL,
                description=f"CRITICAL CORS Misconfiguration: Arbitrary origin '{test_origin}' is reflected with Access-Control-Allow-Credentials: true. Allows cross-origin data theft.",
                remediation="Never dynamically mirror the Origin header when credentials are permitted. Implement a strict whitelist.",
            )

        # Critical/High: Wildcard with credentials (RFC violation & browser blocker)
        if is_wildcard and allow_credentials:
            return CorsFinding(
                test_origin=test_origin,
                allow_origin=acao,
                allow_credentials=acac,
                is_origin_reflected=False,
                is_wildcard_with_credentials=True,
                is_wildcard=True,
                status=AuditStatus.FAILED,
                severity=Severity.HIGH,
                description="Invalid CORS configuration: Access-Control-Allow-Origin: * combined with Access-Control-Allow-Credentials: true.",
                remediation="Remove credentials flag or specify an exact trusted origin instead of wildcard.",
            )

        # High: 'null' origin allowed with credentials
        if test_origin == "null" and acao == "null" and allow_credentials:
            return CorsFinding(
                test_origin="null",
                allow_origin=acao,
                allow_credentials=acac,
                is_origin_reflected=True,
                is_wildcard_with_credentials=False,
                is_wildcard=False,
                status=AuditStatus.FAILED,
                severity=Severity.HIGH,
                description="High Risk: 'null' origin is explicitly trusted with Access-Control-Allow-Credentials: true (exploitable via sandboxed iframes).",
                remediation="Do not trust 'null' origin in CORS configuration.",
            )

        # Medium: Arbitrary origin reflected without credentials
        if is_reflected and not allow_credentials:
            return CorsFinding(
                test_origin=test_origin,
                allow_origin=acao,
                allow_credentials=acac,
                is_origin_reflected=True,
                is_wildcard_with_credentials=False,
                is_wildcard=False,
                status=AuditStatus.WARNING,
                severity=Severity.MEDIUM,
                description=f"Arbitrary origin '{test_origin}' is reflected into Access-Control-Allow-Origin without credentials.",
                remediation="Validate Origin against a server-side whitelist of allowed origins.",
            )

        # Low/Info: Wildcard alone
        if is_wildcard:
            return CorsFinding(
                test_origin=test_origin,
                allow_origin=acao,
                allow_credentials=acac,
                is_origin_reflected=False,
                is_wildcard_with_credentials=False,
                is_wildcard=True,
                status=AuditStatus.WARNING,
                severity=Severity.LOW,
                description="Access-Control-Allow-Origin is set to wildcard '*'. Any website can read response data if not authenticated.",
                remediation="Acceptable for truly public read-only APIs, but restrict if endpoint handles sensitive or private context.",
            )

        return CorsFinding(
            test_origin=test_origin,
            allow_origin=acao,
            allow_credentials=acac,
            is_origin_reflected=False,
            is_wildcard_with_credentials=False,
            is_wildcard=False,
            status=AuditStatus.PASSED,
            severity=Severity.PASS,
            description=f"CORS policy returned non-matching origin '{acao}' for probe '{test_origin}'.",
            remediation="Ensure origin whitelist is kept minimal.",
        )

    @staticmethod
    def _analyze_preflight(headers: httpx.Headers) -> CorsFinding:
        acam = headers.get("access-control-allow-methods")
        acah = headers.get("access-control-allow-headers")

        if not acam and not acah:
            return CorsFinding(
                test_origin="OPTIONS Preflight",
                allow_methods=None,
                allow_headers=None,
                status=AuditStatus.PASSED,
                severity=Severity.PASS,
                description="Preflight OPTIONS request does not expose overly permissive CORS methods/headers.",
                remediation="Continue enforcing explicit preflight rules.",
            )

        if acam and "*" in acam:
            return CorsFinding(
                test_origin="OPTIONS Preflight",
                allow_methods=acam,
                allow_headers=acah,
                status=AuditStatus.WARNING,
                severity=Severity.MEDIUM,
                description=f"Preflight allows wildcard HTTP methods: '{acam}'.",
                remediation="Explicitly enumerate allowed HTTP verbs (e.g. GET, POST, OPTIONS).",
            )

        return CorsFinding(
            test_origin="OPTIONS Preflight",
            allow_methods=acam,
            allow_headers=acah,
            status=AuditStatus.PASSED,
            severity=Severity.PASS,
            description=f"Preflight methods allowed: '{acam or 'None'}'",
            remediation="Regularly review allowed preflight methods and headers.",
        )
