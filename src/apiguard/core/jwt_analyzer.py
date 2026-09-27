"""RFC 7519 JSON Web Token (JWT) structural inspector and security analyzer."""

import base64
from datetime import datetime, timezone
import json
from typing import Any
from apiguard.models.enums import Severity
from apiguard.models.jwt import JwtAnalysisResult, JwtFinding


class JwtAnalyzer:
    """Decodes and audits JWT tokens without signature verification."""

    @classmethod
    def analyze(cls, raw_token: str) -> JwtAnalysisResult:
        """Inspects token headers, claims, temporal validity, and cryptographic indicators."""
        clean_token = raw_token.strip()
        parts = clean_token.split(".")

        if len(parts) not in (2, 3):
            raise ValueError(f"Invalid JWT format: expected 3 dot-separated segments, got {len(parts)}.")

        header_b64 = parts[0]
        payload_b64 = parts[1]
        signature_b64 = parts[2] if len(parts) == 3 else ""

        try:
            header: dict[str, Any] = json.loads(cls._base64url_decode(header_b64))
        except Exception as exc:
            raise ValueError(f"Failed to decode JWT Header: {str(exc)}") from exc

        try:
            payload: dict[str, Any] = json.loads(cls._base64url_decode(payload_b64))
        except Exception as exc:
            raise ValueError(f"Failed to decode JWT Payload: {str(exc)}") from exc

        findings: list[JwtFinding] = []
        now = datetime.now(timezone.utc)

        # 1. Algorithm analysis
        alg = str(header.get("alg", "")).strip()
        is_none = alg.lower() == "none" or alg == ""

        if is_none:
            findings.append(
                JwtFinding(
                    severity=Severity.CRITICAL,
                    title="Insecure Algorithm: 'none'",
                    description="Token algorithm is set to 'none'. Any client can forge arbitrary claims without verification.",
                    remediation="Reject tokens with alg='none' at API gateways. Enforce strong algorithms (RS256, ES256, or robust HS256).",
                )
            )
        elif alg.upper() in ("HS256", "HS384", "HS512"):
            findings.append(
                JwtFinding(
                    severity=Severity.INFO,
                    title=f"Symmetric Algorithm: {alg}",
                    description=f"Token uses symmetric HMAC ({alg}). Ensure secret key has high entropy (>= 256 bits) and is never exposed.",
                    remediation="Consider asymmetric signing (RS256, ES256) if microservices only need to verify tokens.",
                )
            )

        # 2. Key ID (kid) injection check
        kid = header.get("kid")
        if kid and isinstance(kid, str):
            if any(seq in kid for seq in ("..", "/", "\\", "'", "\"", ";", "|", "`")):
                findings.append(
                    JwtFinding(
                        severity=Severity.HIGH,
                        title="Suspicious 'kid' Parameter",
                        description=f"'kid' header contains potential path traversal or injection characters: '{kid}'.",
                        remediation="Strictly sanitize or use an enum/lookup table for key IDs instead of file system paths.",
                    )
                )

        # 3. Timestamp analysis (exp, iat, nbf)
        exp_val = payload.get("exp")
        expires_at: datetime | None = None
        is_expired = False
        time_to_exp: float | None = None

        if exp_val is not None:
            try:
                exp_ts = float(exp_val)
                expires_at = datetime.fromtimestamp(exp_ts, tz=timezone.utc)
                diff = (expires_at - now).total_seconds()
                time_to_exp = diff
                if diff <= 0:
                    is_expired = True
                    findings.append(
                        JwtFinding(
                            severity=Severity.MEDIUM,
                            title="Token Has Expired",
                            description=f"Token expired {abs(int(diff))} seconds ago ({expires_at.isoformat()}).",
                            remediation="Ensure client refreshes expired tokens promptly.",
                        )
                    )
            except (ValueError, TypeError, OverflowError):
                findings.append(
                    JwtFinding(
                        severity=Severity.HIGH,
                        title="Malformed 'exp' Claim",
                        description=f"'exp' claim is not a valid numeric Unix timestamp: {exp_val}",
                        remediation="Emit valid integer Unix epoch timestamps for 'exp'.",
                    )
                )
        else:
            findings.append(
                JwtFinding(
                    severity=Severity.MEDIUM,
                    title="Missing Expiration ('exp') Claim",
                    description="Token does not contain an expiration claim. Stolen tokens remain valid indefinitely.",
                    remediation="Always assign a short, bounded expiration time ('exp') to JWT tokens.",
                )
            )

        # iat (issued at)
        iat_val = payload.get("iat")
        issued_at: datetime | None = None
        if iat_val is not None:
            try:
                iat_ts = float(iat_val)
                issued_at = datetime.fromtimestamp(iat_ts, tz=timezone.utc)
                if (issued_at - now).total_seconds() > 120:
                    findings.append(
                        JwtFinding(
                            severity=Severity.LOW,
                            title="Token Issued in Future",
                            description=f"'iat' is ahead of current server time by {int((issued_at - now).total_seconds())}s (clock skew).",
                            remediation="Synchronize server clocks via NTP.",
                        )
                    )
            except (ValueError, TypeError, OverflowError):
                pass

        # nbf (not before)
        nbf_val = payload.get("nbf")
        not_before: datetime | None = None
        if nbf_val is not None:
            try:
                nbf_ts = float(nbf_val)
                not_before = datetime.fromtimestamp(nbf_ts, tz=timezone.utc)
            except (ValueError, TypeError, OverflowError):
                pass

        # 4. Sensitive data exposure in payload
        cls._check_payload_sensitive_data(payload, findings)

        return JwtAnalysisResult(
            raw_token=clean_token,
            header=header,
            payload=payload,
            signature=signature_b64,
            algorithm=alg or "none",
            is_none_algorithm=is_none,
            issued_at=issued_at,
            expires_at=expires_at,
            not_before=not_before,
            is_expired=is_expired,
            time_to_expiration_seconds=time_to_exp,
            findings=findings,
        )

    @classmethod
    def _check_payload_sensitive_data(cls, payload: dict[str, Any], findings: list[JwtFinding]) -> None:
        """Flags potential cleartext secrets or sensitive PII inside JWT payload."""
        sensitive_keys = {"password", "passwd", "secret", "private_key", "ssn", "credit_card", "cvv"}
        for k in payload.keys():
            if k.lower() in sensitive_keys:
                findings.append(
                    JwtFinding(
                        severity=Severity.HIGH,
                        title=f"Sensitive Field in Payload: '{k}'",
                        description=f"JWT payload contains sensitive claim '{k}'. JWTs are readable by any bearer.",
                        remediation="Never store credentials, raw passwords, or sensitive PII in unencrypted JWT claims.",
                    )
                )

    @staticmethod
    def _base64url_decode(data: str) -> bytes:
        """Decodes standard Base64URL string by restoring padding."""
        padding = 4 - (len(data) % 4)
        if padding != 4:
            data += "=" * padding
        return base64.urlsafe_b64decode(data)
