"""Enumeration types for APIGuard compliance and audit results."""

from enum import Enum


class Severity(str, Enum):
    """Vulnerability and compliance finding severity levels."""
    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    INFO = "INFO"
    PASS = "PASS"

    @property
    def score_penalty(self) -> int:
        """Penalty deducted from base score (100) per finding."""
        penalties = {
            Severity.CRITICAL: 25,
            Severity.HIGH: 15,
            Severity.MEDIUM: 8,
            Severity.LOW: 3,
            Severity.INFO: 0,
            Severity.PASS: 0,
        }
        return penalties.get(self, 0)

    @property
    def color(self) -> str:
        """Rich terminal color code for this severity level."""
        colors = {
            Severity.CRITICAL: "bold red",
            Severity.HIGH: "red",
            Severity.MEDIUM: "yellow",
            Severity.LOW: "cyan",
            Severity.INFO: "blue",
            Severity.PASS: "bold green",
        }
        return colors.get(self, "white")


class AuditStatus(str, Enum):
    """Status outcome for an audit check."""
    PASSED = "PASSED"
    WARNING = "WARNING"
    FAILED = "FAILED"
    SKIPPED = "SKIPPED"


class CheckCategory(str, Enum):
    """Categorization for compliance checks."""
    SECURITY_HEADERS = "Security Headers"
    CORS_POLICY = "CORS Configuration"
    ENDPOINT_EXPOSURE = "Endpoint & Metadata Exposure"
    JWT_CRYPTOGRAPHY = "JWT Cryptography & Claims"
