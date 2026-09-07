#!/usr/bin/env python3
"""
Canary Test Suite: JWT "none" Algorithm Attack
================================================
This file DELIBERATELY contains the JWT none-algorithm vulnerability.
It exists to validate that the scanner pipeline detects it.

Expected detections: Semgrep (custom rule: jwt-none-alg)
"""

# Import the standard JWT library pattern used in this project
try:
    import jwt  # PyJWT
except ImportError:
    jwt = None


def verify_token_vulnerable(token: str):
    """
    VULNERABLE: jwt.decode() without specifying allowed algorithms.
    An attacker can craft a token with alg=none and bypass signature verification.
    """
    # No 'algorithms' parameter → accepts 'none' algorithm
    payload = jwt.decode(token, SECRET_KEY)
    return payload


def verify_token_vulnerable_2(token: str):
    """
    VULNERABLE: Explicit verification bypass.
    """
    payload = jwt.decode(token, SECRET_KEY, options={"verify_signature": False})
    return payload


# ── SAFE version (for contrast) ─────────────────────────────────────────────
def verify_token_safe(token: str):
    """SAFE: explicitly restrict to HS256 algorithm."""
    return jwt.decode(token, SECRET_KEY, algorithms=["HS256"])


SECRET_KEY = "dev-secret-key-change-in-production"
