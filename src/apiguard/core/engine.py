"""Asynchronous audit engine coordinating network probes, security checks, and reporting."""

import time
from typing import Optional
from urllib.parse import urlparse
import httpx

from apiguard.core.cors import CorsAuditor
from apiguard.core.endpoints import EndpointScanner
from apiguard.core.headers import HeaderAuditor
from apiguard.models.audit import AuditReport


class AuditEngine:
    """Orchestrates comprehensive black-box compliance auditing against a target REST API."""

    def __init__(
        self,
        timeout: float = 10.0,
        verify_ssl: bool = True,
        custom_headers: Optional[dict[str, str]] = None,
        concurrency: int = 5,
    ) -> None:
        self.timeout = timeout
        self.verify_ssl = verify_ssl
        self.custom_headers = custom_headers or {}
        self.concurrency = concurrency

    async def run_audit(
        self,
        target_url: str,
        custom_endpoints: Optional[list[str]] = None,
    ) -> AuditReport:
        """Executes full compliance audit against the specified URL."""
        # Ensure scheme is present
        parsed = urlparse(target_url)
        if not parsed.scheme:
            target_url = "https://" + target_url
            parsed = urlparse(target_url)

        is_https = parsed.scheme.lower() == "https"
        start_time = time.perf_counter()

        client_headers = {
            "User-Agent": "APIGuard-Linter/0.1.0 (Compliance Auditor)",
            **self.custom_headers,
        }

        async with httpx.AsyncClient(
            headers=client_headers,
            timeout=self.timeout,
            verify=self.verify_ssl,
            follow_redirects=True,
        ) as client:
            # 1. Base endpoint check
            resp = await client.get(target_url)
            base_headers = resp.headers

            # 2. Security Headers audit
            header_findings = HeaderAuditor.audit(base_headers, is_https=is_https)

            # 3. CORS configuration audit
            cors_findings = await CorsAuditor.audit(client, target_url)

            # 4. Sensitive & diagnostic endpoints audit
            endpoint_findings = await EndpointScanner.scan(
                client=client,
                base_url=target_url,
                custom_paths=custom_endpoints,
                concurrency=self.concurrency,
            )

        elapsed = time.perf_counter() - start_time

        report = AuditReport(
            target_url=target_url,
            duration_seconds=round(elapsed, 2),
            header_findings=header_findings,
            cors_findings=cors_findings,
            endpoint_findings=endpoint_findings,
        )
        report.compute_score_and_grade()
        return report
