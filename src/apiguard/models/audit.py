"""Pydantic v2 data models for API audit findings and compliance reports."""

from datetime import datetime, timezone
from typing import Optional
from pydantic import BaseModel, Field

from apiguard.models.enums import AuditStatus, Severity


class HeaderFinding(BaseModel):
    """Result of analyzing an individual HTTP security header."""
    header_name: str
    present: bool
    value: Optional[str] = None
    status: AuditStatus
    severity: Severity
    description: str
    remediation: str


class CorsFinding(BaseModel):
    """Result of evaluating Cross-Origin Resource Sharing (CORS) behavior."""
    test_origin: str
    allow_origin: Optional[str] = None
    allow_credentials: Optional[str] = None
    allow_methods: Optional[str] = None
    allow_headers: Optional[str] = None
    is_origin_reflected: bool = False
    is_wildcard_with_credentials: bool = False
    is_wildcard: bool = False
    status: AuditStatus
    severity: Severity
    description: str
    remediation: str


class EndpointFinding(BaseModel):
    """Result of testing an exposed diagnostic or metadata endpoint."""
    path: str
    status_code: Optional[int] = None
    is_exposed: bool = False
    content_type: Optional[str] = None
    severity: Severity
    risk_description: str
    sample_snippet: Optional[str] = None
    remediation: str


class AuditReport(BaseModel):
    """Comprehensive compliance audit report for a target URL."""
    target_url: str
    timestamp: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    duration_seconds: float = 0.0
    score: int = Field(default=100, ge=0, le=100)
    grade: str = "A+"
    header_findings: list[HeaderFinding] = Field(default_factory=list)
    cors_findings: list[CorsFinding] = Field(default_factory=list)
    endpoint_findings: list[EndpointFinding] = Field(default_factory=list)

    @property
    def critical_count(self) -> int:
        return self._count_severity(Severity.CRITICAL)

    @property
    def high_count(self) -> int:
        return self._count_severity(Severity.HIGH)

    @property
    def medium_count(self) -> int:
        return self._count_severity(Severity.MEDIUM)

    @property
    def low_count(self) -> int:
        return self._count_severity(Severity.LOW)

    @property
    def info_count(self) -> int:
        return self._count_severity(Severity.INFO)

    def _count_severity(self, severity: Severity) -> int:
        count = sum(1 for f in self.header_findings if f.severity == severity)
        count += sum(1 for f in self.cors_findings if f.severity == severity)
        count += sum(1 for f in self.endpoint_findings if f.severity == severity)
        return count

    def compute_score_and_grade(self) -> None:
        """Calculates security compliance score (0-100) and letter grade."""
        total_penalty = 0
        for f in self.header_findings:
            total_penalty += f.severity.score_penalty
        for f in self.cors_findings:
            total_penalty += f.severity.score_penalty
        for f in self.endpoint_findings:
            if f.is_exposed:
                total_penalty += f.severity.score_penalty

        raw_score = max(0, 100 - total_penalty)
        self.score = raw_score

        if self.score >= 95 and self.critical_count == 0 and self.high_count == 0:
            self.grade = "A+"
        elif self.score >= 90 and self.critical_count == 0:
            self.grade = "A"
        elif self.score >= 80 and self.critical_count == 0:
            self.grade = "B"
        elif self.score >= 70:
            self.grade = "C"
        elif self.score >= 60:
            self.grade = "D"
        else:
            self.grade = "F"
