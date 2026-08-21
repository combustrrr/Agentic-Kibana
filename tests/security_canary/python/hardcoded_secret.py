#!/usr/bin/env python3
"""
Canary Test Suite: Hardcoded Secrets / Credentials
===================================================
This file DELIBERATELY contains hardcoded secrets.
It exists to validate that the scanner pipeline detects credential leaks.

NEVER commit real credentials. These are intentional test patterns.

Expected detections: Bandit (B105/B106), Gitleaks, Semgrep
"""

import os

# ── Pattern 1: Hardcoded API key ─────────────────────────────────────────────
OPENAI_API_KEY = "sk-proj-1234567890abcdefghijklmnopqrstuvwxyz"
ANTHROPIC_API_KEY = "sk-ant-api03-1234567890ABCDEFGHIJKLMNOPQRSTUVWXYZ"


# ── Pattern 2: Hardcoded database password ───────────────────────────────────
DB_PASSWORD = "SuperSecret123!"
DATABASE_URL = "postgresql://admin:s3cr3tP@ss@localhost:5432/db"


# ── Pattern 3: Hardcoded JWT secret ──────────────────────────────────────────
JWT_SECRET = "my-super-secret-key-for-jwt-signing-min-32-chars"
JWT_SECRET_KEY = "dGhpcyBpcyBhbiB1bmNvZGUgbmV0c2VjcmV0"


# ── Pattern 4: Redis URL with embedded password ──────────────────────────────
REDIS_URL = "redis://:redacted_password_123@redis.example.com:6379/0"


# ── Pattern 5: Generic secret variable ───────────────────────────────────────
API_TOKEN = "ghp_1234567890abcdefghijklmnopqrstuvwxyzABCD"
SECRET_KEY = "flask-secret-key-do-not-use-in-production-12345"


# ── SAFE version (for contrast) ─────────────────────────────────────────────
def get_api_key():
    """SAFE: read from environment."""
    return os.environ.get("API_KEY")
