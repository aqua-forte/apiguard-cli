"""Pydantic v2 data models for JWT inspection and cryptographic resilience testing."""

from datetime import datetime
from typing import Any, Optional
from pydantic import BaseModel, Field

from apiguard.models.enums import Severity


class JwtFinding(BaseModel):
    """Specific vulnerability or security observation in a token."""
    severity: Severity
    title: str
    description: str
    remediation: str


class JwtAnalysisResult(BaseModel):
    """Detailed structural and cryptographic inspection results for a JWT."""
    raw_token: str
    header: dict[str, Any] = Field(default_factory=dict)
    payload: dict[str, Any] = Field(default_factory=dict)
    signature: str = ""
    algorithm: str = "unknown"
    is_none_algorithm: bool = False
    issued_at: Optional[datetime] = None
    expires_at: Optional[datetime] = None
    not_before: Optional[datetime] = None
    is_expired: bool = False
    time_to_expiration_seconds: Optional[float] = None
    findings: list[JwtFinding] = Field(default_factory=list)

    @property
    def has_critical_findings(self) -> bool:
        return any(f.severity == Severity.CRITICAL for f in self.findings)


class JwtStrengthResult(BaseModel):
    """Outcome of dictionary-based HMAC secret resilience testing."""
    algorithm: str
    is_weak: bool = False
    cracked_secret: Optional[str] = None
    candidates_tested: int = 0
    duration_ms: float = 0.0
    hashes_per_second: float = 0.0
    description: str = ""
    remediation: str = ""
