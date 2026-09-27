"""Cryptographic resilience and HMAC secret auditor for JSON Web Tokens."""

import base64
import hashlib
import hmac
import time
from typing import Iterable, Optional

from apiguard.models.jwt import JwtStrengthResult


class JwtStrengthAuditor:
    """Tests resilience of HMAC-signed JWTs against common weak default secrets."""

    DEFAULT_SECRETS: list[str] = [
        "secret",
        "secret123",
        "password",
        "password123",
        "123456",
        "12345678",
        "123456789",
        "admin",
        "admin123",
        "jwt",
        "jwtsecret",
        "jwt_secret",
        "key",
        "mykey",
        "supersecret",
        "development",
        "dev",
        "production",
        "test",
        "testing",
        "app",
        "api",
        "apikey",
        "auth",
        "authentication",
        "changeme",
        "default",
        "root",
        "master",
        "welcome",
        "system",
        "server",
        "database",
        "login",
        "token",
        "access",
        "qwerty",
        "iloveyou",
        "letmein",
        "secretkey",
        "topsecret",
        "security",
        "demo",
        "sample",
        "public",
        "private",
    ]

    HASH_ALG_MAP = {
        "HS256": hashlib.sha256,
        "HS384": hashlib.sha384,
        "HS512": hashlib.sha512,
    }

    @classmethod
    def test_strength(
        cls,
        raw_token: str,
        custom_wordlist: Optional[Iterable[str]] = None,
    ) -> JwtStrengthResult:
        """Audits whether token's HMAC signature matches common weak secrets."""
        parts = raw_token.strip().split(".")
        if len(parts) != 3:
            raise ValueError(f"Invalid JWT format: expected 3 dot-separated segments, got {len(parts)}.")

        header_b64, payload_b64, signature_b64 = parts
        signing_input = f"{header_b64}.{payload_b64}".encode("ascii")

        # Decode header to identify algorithm
        try:
            pad = 4 - (len(header_b64) % 4)
            if pad != 4:
                header_b64_padded = header_b64 + ("=" * pad)
            else:
                header_b64_padded = header_b64
            import json
            hdr = json.loads(base64.urlsafe_b64decode(header_b64_padded))
            alg = str(hdr.get("alg", "HS256")).upper()
        except Exception:
            alg = "HS256"

        hash_func = cls.HASH_ALG_MAP.get(alg)
        if not hash_func:
            return JwtStrengthResult(
                algorithm=alg,
                is_weak=False,
                cracked_secret=None,
                candidates_tested=0,
                duration_ms=0.0,
                hashes_per_second=0.0,
                description=f"Algorithm '{alg}' is not an HMAC symmetric algorithm (HS256/384/512). Secret wordlist audit is not applicable.",
                remediation="Ensure asymmetric private key is protected in a hardware security module (HSM) or secure vault.",
            )

        # Standardize target signature
        target_sig_clean = signature_b64.rstrip("=")

        wordlist = custom_wordlist if custom_wordlist is not None else cls.DEFAULT_SECRETS
        candidates_count = 0
        cracked_key: Optional[str] = None

        start_time = time.perf_counter()

        for candidate in wordlist:
            candidate_str = candidate.strip()
            if not candidate_str:
                continue
            candidates_count += 1

            candidate_key = candidate_str.encode("utf-8")
            h = hmac.new(candidate_key, signing_input, hash_func)
            computed_sig = base64.urlsafe_b64encode(h.digest()).decode("ascii").rstrip("=")

            if hmac.compare_digest(computed_sig, target_sig_clean):
                cracked_key = candidate_str
                break

        elapsed = time.perf_counter() - start_time
        duration_ms = round(elapsed * 1000, 2)
        hps = round(candidates_count / elapsed, 2) if elapsed > 0 else 0.0

        if cracked_key is not None:
            return JwtStrengthResult(
                algorithm=alg,
                is_weak=True,
                cracked_secret=cracked_key,
                candidates_tested=candidates_count,
                duration_ms=duration_ms,
                hashes_per_second=hps,
                description=f"CRITICAL VULNERABILITY: Token signature verified using weak dictionary secret: '{cracked_key}'! Attackers can forge arbitrary administrative tokens.",
                remediation="Immediately rotate the signing secret to a cryptographically secure random key (minimum 256 bits of entropy, e.g. `openssl rand -hex 32`).",
            )

        return JwtStrengthResult(
            algorithm=alg,
            is_weak=False,
            cracked_secret=None,
            candidates_tested=candidates_count,
            duration_ms=duration_ms,
            hashes_per_second=hps,
            description=f"No weak secret matches found across {candidates_count} tested candidate keys.",
            remediation="Ensure production secrets are securely stored and rotated on a periodic schedule.",
        )
