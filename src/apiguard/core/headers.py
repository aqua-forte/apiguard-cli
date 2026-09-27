"""Security headers analyzer adhering to OWASP and RFC compliance baselines."""

import re
from typing import Mapping
from apiguard.models.audit import HeaderFinding
from apiguard.models.enums import AuditStatus, Severity


class HeaderAuditor:
    """Evaluates HTTP response headers against modern security baselines."""

    @classmethod
    def audit(cls, headers: Mapping[str, str], is_https: bool = True) -> list[HeaderFinding]:
        """Runs compliance checks on given HTTP response headers."""
        findings: list[HeaderFinding] = []
        normalized = {k.lower(): v.strip() for k, v in headers.items()}

        findings.append(cls._check_csp(normalized))
        findings.append(cls._check_hsts(normalized, is_https))
        findings.append(cls._check_x_content_type_options(normalized))
        findings.append(cls._check_x_frame_options(normalized))
        findings.append(cls._check_referrer_policy(normalized))
        findings.append(cls._check_permissions_policy(normalized))

        # Check for information leakage
        info_leak = cls._check_information_disclosure(normalized)
        if info_leak:
            findings.extend(info_leak)

        return findings

    @staticmethod
    def _check_csp(headers: dict[str, str]) -> HeaderFinding:
        csp = headers.get("content-security-policy")
        if not csp:
            return HeaderFinding(
                header_name="Content-Security-Policy",
                present=False,
                value=None,
                status=AuditStatus.FAILED,
                severity=Severity.HIGH,
                description="Header is missing. Browser is vulnerable to Cross-Site Scripting (XSS) and injection.",
                remediation="Configure a restrictive Content-Security-Policy (e.g., \"default-src 'none'; frame-ancestors 'none'\").",
            )

        # Insecure CSP directives check
        lower_csp = csp.lower()
        weaknesses = []
        if "'unsafe-inline'" in lower_csp and "nonce-" not in lower_csp and "sha256-" not in lower_csp:
            weaknesses.append("'unsafe-inline' without nonce/hash")
        if "'unsafe-eval'" in lower_csp:
            weaknesses.append("'unsafe-eval'")
        if "default-src *" in lower_csp:
            weaknesses.append("wildcard default-src")

        if weaknesses:
            return HeaderFinding(
                header_name="Content-Security-Policy",
                present=True,
                value=csp,
                status=AuditStatus.WARNING,
                severity=Severity.MEDIUM,
                description=f"CSP contains permissive directive(s): {', '.join(weaknesses)}.",
                remediation="Remove unsafe directives, use strict nonces or hashes for scripts.",
            )

        return HeaderFinding(
            header_name="Content-Security-Policy",
            present=True,
            value=csp,
            status=AuditStatus.PASSED,
            severity=Severity.PASS,
            description="Content-Security-Policy is present and configured without obvious wildcard/unsafe directives.",
            remediation="Ensure policy is regularly audited against application changes.",
        )

    @staticmethod
    def _check_hsts(headers: dict[str, str], is_https: bool) -> HeaderFinding:
        hsts = headers.get("strict-transport-security")
        if not is_https:
            return HeaderFinding(
                header_name="Strict-Transport-Security",
                present=bool(hsts),
                value=hsts,
                status=AuditStatus.SKIPPED,
                severity=Severity.INFO,
                description="Target is served over unencrypted HTTP. HSTS cannot be evaluated.",
                remediation="Enforce HTTPS across all API endpoints.",
            )

        if not hsts:
            return HeaderFinding(
                header_name="Strict-Transport-Security",
                present=False,
                value=None,
                status=AuditStatus.FAILED,
                severity=Severity.HIGH,
                description="Missing HSTS header. Connections are vulnerable to SSL-stripping and downgrade attacks.",
                remediation="Add Strict-Transport-Security: max-age=31536000; includeSubDomains; preload",
            )

        max_age_match = re.search(r"max-age=(\d+)", hsts.lower())
        if not max_age_match:
            return HeaderFinding(
                header_name="Strict-Transport-Security",
                present=True,
                value=hsts,
                status=AuditStatus.WARNING,
                severity=Severity.MEDIUM,
                description="HSTS header present but missing valid max-age directive.",
                remediation="Specify a max-age directive of at least 31536000 seconds (1 year).",
            )

        max_age = int(max_age_match.group(1))
        if max_age < 15552000:  # < 180 days
            return HeaderFinding(
                header_name="Strict-Transport-Security",
                present=True,
                value=hsts,
                status=AuditStatus.WARNING,
                severity=Severity.LOW,
                description=f"HSTS max-age is set to {max_age}s, which is below recommended 31536000s.",
                remediation="Increase max-age to at least 31536000 (1 year) and includeSubDomains.",
            )

        return HeaderFinding(
            header_name="Strict-Transport-Security",
            present=True,
            value=hsts,
            status=AuditStatus.PASSED,
            severity=Severity.PASS,
            description="Strict-Transport-Security correctly configured with sufficient duration.",
            remediation="Consider adding 'preload' directive for HSTS browser preload lists.",
        )

    @staticmethod
    def _check_x_content_type_options(headers: dict[str, str]) -> HeaderFinding:
        xcto = headers.get("x-content-type-options")
        if not xcto:
            return HeaderFinding(
                header_name="X-Content-Type-Options",
                present=False,
                value=None,
                status=AuditStatus.FAILED,
                severity=Severity.MEDIUM,
                description="Missing X-Content-Type-Options. Clients may MIME-sniff response bodies as executable types.",
                remediation="Add X-Content-Type-Options: nosniff",
            )

        if xcto.lower() != "nosniff":
            return HeaderFinding(
                header_name="X-Content-Type-Options",
                present=True,
                value=xcto,
                status=AuditStatus.WARNING,
                severity=Severity.LOW,
                description=f"X-Content-Type-Options is '{xcto}' instead of recommended 'nosniff'.",
                remediation="Set X-Content-Type-Options: nosniff exactly.",
            )

        return HeaderFinding(
            header_name="X-Content-Type-Options",
            present=True,
            value=xcto,
            status=AuditStatus.PASSED,
            severity=Severity.PASS,
            description="X-Content-Type-Options is correctly set to nosniff.",
            remediation="Maintain nosniff policy across all MIME types.",
        )

    @staticmethod
    def _check_x_frame_options(headers: dict[str, str]) -> HeaderFinding:
        xfo = headers.get("x-frame-options")
        if not xfo:
            return HeaderFinding(
                header_name="X-Frame-Options",
                present=False,
                value=None,
                status=AuditStatus.FAILED,
                severity=Severity.MEDIUM,
                description="Missing X-Frame-Options. Endpoint may be embedded into frames, enabling Clickjacking.",
                remediation="Add X-Frame-Options: DENY or SAMEORIGIN (or frame-ancestors 'none' in CSP).",
            )

        val_upper = xfo.upper()
        if val_upper not in ("DENY", "SAMEORIGIN"):
            return HeaderFinding(
                header_name="X-Frame-Options",
                present=True,
                value=xfo,
                status=AuditStatus.WARNING,
                severity=Severity.LOW,
                description=f"Non-standard X-Frame-Options value: '{xfo}'.",
                remediation="Use DENY or SAMEORIGIN.",
            )

        return HeaderFinding(
            header_name="X-Frame-Options",
            present=True,
            value=xfo,
            status=AuditStatus.PASSED,
            severity=Severity.PASS,
            description=f"X-Frame-Options configured as {val_upper}.",
            remediation="Maintain DENY or SAMEORIGIN setting.",
        )

    @staticmethod
    def _check_referrer_policy(headers: dict[str, str]) -> HeaderFinding:
        rp = headers.get("referrer-policy")
        if not rp:
            return HeaderFinding(
                header_name="Referrer-Policy",
                present=False,
                value=None,
                status=AuditStatus.WARNING,
                severity=Severity.LOW,
                description="Missing Referrer-Policy. Sensitive query params or path details might leak to third parties.",
                remediation="Add Referrer-Policy: strict-origin-when-cross-origin or no-referrer",
            )

        if "unsafe-url" in rp.lower():
            return HeaderFinding(
                header_name="Referrer-Policy",
                present=True,
                value=rp,
                status=AuditStatus.FAILED,
                severity=Severity.MEDIUM,
                description="Referrer-Policy configured with insecure 'unsafe-url' directive.",
                remediation="Replace with strict-origin-when-cross-origin or no-referrer.",
            )

        return HeaderFinding(
            header_name="Referrer-Policy",
            present=True,
            value=rp,
            status=AuditStatus.PASSED,
            severity=Severity.PASS,
            description=f"Referrer-Policy configured as '{rp}'.",
            remediation="Ensure referrer header strips sensitive tokens.",
        )

    @staticmethod
    def _check_permissions_policy(headers: dict[str, str]) -> HeaderFinding:
        pp = headers.get("permissions-policy") or headers.get("feature-policy")
        if not pp:
            return HeaderFinding(
                header_name="Permissions-Policy",
                present=False,
                value=None,
                status=AuditStatus.WARNING,
                severity=Severity.LOW,
                description="Missing Permissions-Policy. Browser hardware APIs (camera, microphone, geolocation) not restricted.",
                remediation="Add Permissions-Policy: camera=(), microphone=(), geolocation=()",
            )

        return HeaderFinding(
            header_name="Permissions-Policy",
            present=True,
            value=pp,
            status=AuditStatus.PASSED,
            severity=Severity.PASS,
            description="Permissions-Policy is present.",
            remediation="Keep permissions policy synchronized with required browser APIs.",
        )

    @staticmethod
    def _check_information_disclosure(headers: dict[str, str]) -> list[HeaderFinding]:
        findings = []
        server = headers.get("server")
        if server:
            # Check if version is exposed (e.g. Apache/2.4.41 or nginx/1.18.0)
            has_version = bool(re.search(r"\d+\.\d+", server))
            findings.append(
                HeaderFinding(
                    header_name="Server",
                    present=True,
                    value=server,
                    status=AuditStatus.WARNING if has_version else AuditStatus.PASSED,
                    severity=Severity.LOW if has_version else Severity.INFO,
                    description=f"Server header exposes banner: '{server}'" + (" (software version leaked)" if has_version else ""),
                    remediation="Disable or sanitize Server response header to prevent fingerprinting.",
                )
            )

        powered_by = headers.get("x-powered-by")
        if powered_by:
            findings.append(
                HeaderFinding(
                    header_name="X-Powered-By",
                    present=True,
                    value=powered_by,
                    status=AuditStatus.WARNING,
                    severity=Severity.LOW,
                    description=f"Backend technology fingerprint leaked: '{powered_by}'.",
                    remediation="Remove X-Powered-By header in web framework / reverse proxy configuration.",
                )
            )

        return findings
