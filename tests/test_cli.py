"""End-to-end tests for APIGuard Typer CLI commands."""

import json
from unittest.mock import AsyncMock, patch
from typer.testing import CliRunner

from apiguard.cli.main import app
from apiguard.models.audit import AuditReport, HeaderFinding
from apiguard.models.enums import AuditStatus, Severity

runner = CliRunner()


def test_cli_version():
    result = runner.invoke(app, ["--version"])
    assert result.exit_code == 0
    assert "apiguard version 0.1.0" in result.stdout


def test_cli_help():
    result = runner.invoke(app, ["--help"])
    assert result.exit_code == 0
    assert "APIGuard: Automated REST API Health & Security Compliance Linter" in result.stdout


def test_cli_jwt_inspect(sample_valid_jwt):
    result = runner.invoke(app, ["jwt", "inspect", sample_valid_jwt])
    assert result.exit_code == 0
    assert "JWT HEADER METADATA" in result.stdout
    assert "user_12345" in result.stdout


def test_cli_jwt_inspect_json(sample_valid_jwt):
    result = runner.invoke(app, ["jwt", "inspect", sample_valid_jwt, "--format", "json"])
    assert result.exit_code == 0
    data = json.loads(result.stdout)
    assert data["algorithm"] == "HS256"
    assert data["payload"]["sub"] == "user_12345"


def test_cli_jwt_inspect_invalid_token():
    result = runner.invoke(app, ["jwt", "inspect", "invalid_jwt_format"])
    assert result.exit_code == 1
    assert "JWT analysis error" in result.stderr or "JWT analysis error" in result.stdout


def test_cli_jwt_verify_strength_weak(sample_weak_secret_jwt):
    result = runner.invoke(app, ["jwt", "verify-strength", sample_weak_secret_jwt])
    assert result.exit_code == 0
    assert "HMAC RESILIENCE BENCHMARK" in result.stdout
    assert "password123" in result.stdout


def test_cli_jwt_verify_strength_json(sample_weak_secret_jwt):
    result = runner.invoke(app, ["jwt", "verify-strength", sample_weak_secret_jwt, "--format", "json"])
    assert result.exit_code == 0
    data = json.loads(result.stdout)
    assert data["is_weak"] is True
    assert data["cracked_secret"] == "password123"


def test_cli_audit_mocked(tmp_path):
    mock_report = AuditReport(
        target_url="https://api.test-target.com",
        duration_seconds=0.45,
        score=92,
        grade="A",
        header_findings=[
            HeaderFinding(
                header_name="Content-Security-Policy",
                present=True,
                value="default-src 'self'",
                status=AuditStatus.PASSED,
                severity=Severity.PASS,
                description="Valid CSP",
                remediation="Keep updated",
            )
        ],
        cors_findings=[],
        endpoint_findings=[],
    )

    out_file = tmp_path / "report.json"

    with patch("apiguard.core.engine.AuditEngine.run_audit", new_callable=AsyncMock) as mock_run:
        mock_run.return_value = mock_report
        result = runner.invoke(app, ["audit", "https://api.test-target.com", "--output", str(out_file)])
        assert result.exit_code == 0
        assert "EXECUTIVE AUDIT SUMMARY" in result.stdout
        assert "api.test-target.com" in result.stdout
        assert out_file.exists()


def test_cli_audit_json_format():
    mock_report = AuditReport(
        target_url="https://api.test-target.com",
        duration_seconds=0.1,
        score=100,
        grade="A+",
        header_findings=[],
        cors_findings=[],
        endpoint_findings=[],
    )

    with patch("apiguard.core.engine.AuditEngine.run_audit", new_callable=AsyncMock) as mock_run:
        mock_run.return_value = mock_report
        result = runner.invoke(app, ["audit", "https://api.test-target.com", "--format", "json"])
        assert result.exit_code == 0
        data = json.loads(result.stdout)
        assert data["target_url"] == "https://api.test-target.com"
        assert data["score"] == 100
