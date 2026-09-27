"""Unit tests for HTTP security headers evaluation logic."""

import pytest
from apiguard.core.headers import HeaderAuditor
from apiguard.models.enums import AuditStatus, Severity


def test_secure_headers_all_pass(sample_secure_headers):
    findings = HeaderAuditor.audit(sample_secure_headers, is_https=True)
    assert len(findings) == 6
    for f in findings:
        assert f.status == AuditStatus.PASSED
        assert f.severity == Severity.PASS


def test_missing_headers_reported():
    empty_headers = {}
    findings = HeaderAuditor.audit(empty_headers, is_https=True)
    names = {f.header_name: f for f in findings}

    assert names["Content-Security-Policy"].status == AuditStatus.FAILED
    assert names["Content-Security-Policy"].severity == Severity.HIGH

    assert names["Strict-Transport-Security"].status == AuditStatus.FAILED
    assert names["Strict-Transport-Security"].severity == Severity.HIGH

    assert names["X-Content-Type-Options"].status == AuditStatus.FAILED
    assert names["X-Content-Type-Options"].severity == Severity.MEDIUM

    assert names["X-Frame-Options"].status == AuditStatus.FAILED
    assert names["X-Frame-Options"].severity == Severity.MEDIUM

    assert names["Referrer-Policy"].status == AuditStatus.WARNING
    assert names["Permissions-Policy"].status == AuditStatus.WARNING


def test_hsts_skipped_on_http():
    findings = HeaderAuditor.audit({}, is_https=False)
    hsts_finding = next(f for f in findings if f.header_name == "Strict-Transport-Security")
    assert hsts_finding.status == AuditStatus.SKIPPED
    assert hsts_finding.severity == Severity.INFO


def test_hsts_low_max_age():
    headers = {"strict-transport-security": "max-age=86400"}
    findings = HeaderAuditor.audit(headers, is_https=True)
    hsts_finding = next(f for f in findings if f.header_name == "Strict-Transport-Security")
    assert hsts_finding.status == AuditStatus.WARNING
    assert hsts_finding.severity == Severity.LOW
    assert "86400" in hsts_finding.description


def test_csp_unsafe_directives():
    headers = {"content-security-policy": "default-src 'self'; script-src 'unsafe-inline' 'unsafe-eval'"}
    findings = HeaderAuditor.audit(headers, is_https=True)
    csp_finding = next(f for f in findings if f.header_name == "Content-Security-Policy")
    assert csp_finding.status == AuditStatus.WARNING
    assert csp_finding.severity == Severity.MEDIUM
    assert "'unsafe-inline'" in csp_finding.description


def test_information_leakage(sample_insecure_headers):
    findings = HeaderAuditor.audit(sample_insecure_headers, is_https=True)
    server_finding = next((f for f in findings if f.header_name == "Server"), None)
    powered_by_finding = next((f for f in findings if f.header_name == "X-Powered-By"), None)

    assert server_finding is not None
    assert server_finding.status == AuditStatus.WARNING
    assert "Apache/2.4.41" in server_finding.value

    assert powered_by_finding is not None
    assert powered_by_finding.status == AuditStatus.WARNING
    assert "PHP/7.4.3" in powered_by_finding.value
