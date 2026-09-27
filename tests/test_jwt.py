"""Unit tests for JWT parsing, claims auditing, and HMAC strength testing."""

import pytest
from apiguard.core.jwt_analyzer import JwtAnalyzer
from apiguard.core.jwt_strength import JwtStrengthAuditor
from apiguard.models.enums import Severity


def test_jwt_valid_analysis(sample_valid_jwt):
    res = JwtAnalyzer.analyze(sample_valid_jwt)

    assert res.algorithm == "HS256"
    assert not res.is_none_algorithm
    assert not res.is_expired
    assert res.payload["sub"] == "user_12345"
    assert res.payload["role"] == "compliance_analyst"
    assert res.expires_at is not None
    assert not res.has_critical_findings


def test_jwt_expired_token(sample_expired_jwt):
    res = JwtAnalyzer.analyze(sample_expired_jwt)

    assert res.is_expired
    assert any("Expired" in f.title for f in res.findings)


def test_jwt_none_algorithm_critical(sample_none_alg_jwt):
    res = JwtAnalyzer.analyze(sample_none_alg_jwt)

    assert res.is_none_algorithm
    assert res.has_critical_findings
    crit = next(f for f in res.findings if f.severity == Severity.CRITICAL)
    assert "'none'" in crit.title


def test_jwt_sensitive_claim_exposure():
    from tests.conftest import make_jwt
    token = make_jwt(
        {"alg": "HS256"},
        {"sub": "user_1", "password": "CleartextDbPassword!", "exp": 2000000000},
    )
    res = JwtAnalyzer.analyze(token)
    assert any("Sensitive Field" in f.title for f in res.findings)


def test_jwt_invalid_format():
    with pytest.raises(ValueError, match="Invalid JWT format"):
        JwtAnalyzer.analyze("not.a.valid.jwt.with.too.many.dots")

    with pytest.raises(ValueError, match="Failed to decode JWT Header"):
        JwtAnalyzer.analyze("!!!invalidbase64!!!.payload.sig")


def test_jwt_verify_strength_weak_secret(sample_weak_secret_jwt):
    res = JwtStrengthAuditor.test_strength(sample_weak_secret_jwt)

    assert res.is_weak
    assert res.cracked_secret == "password123"
    assert res.candidates_tested > 0
    assert res.duration_ms >= 0.0
    assert res.hashes_per_second >= 0.0
    assert "CRITICAL VULNERABILITY" in res.description


def test_jwt_verify_strength_strong_secret(sample_valid_jwt):
    res = JwtStrengthAuditor.test_strength(sample_valid_jwt)

    assert not res.is_weak
    assert res.cracked_secret is None
    assert res.candidates_tested > 0
    assert "No weak secret matches found" in res.description


def test_jwt_verify_strength_custom_wordlist(sample_weak_secret_jwt):
    res = JwtStrengthAuditor.test_strength(
        sample_weak_secret_jwt,
        custom_wordlist=["foo", "bar", "password123", "baz"],
    )
    assert res.is_weak
    assert res.cracked_secret == "password123"
    assert res.candidates_tested == 3


def test_jwt_verify_strength_non_hmac(sample_none_alg_jwt):
    res = JwtStrengthAuditor.test_strength(sample_none_alg_jwt)
    assert not res.is_weak
    assert "is not an HMAC symmetric algorithm" in res.description
