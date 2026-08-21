#!/usr/bin/env python3
"""
Canary Test Suite: Unsafe Pickle Deserialization
================================================
This file DELIBERATELY contains unsafe deserialization.
It exists to validate that the scanner pipeline detects it.

Expected detections: Bandit (B301/B302), Semgrep (custom rule)
"""

import pickle
import yaml


# ── Pattern 1: pickle.loads() on untrusted data ──────────────────────────────
def load_user_session(data: bytes):
    """VULNERABLE: pickle.loads() on untrusted input."""
    obj = pickle.loads(data)
    return obj


# ── Pattern 2: pickle.load() from file ───────────────────────────────────────
def load_config_file(filepath: str):
    """VULNERABLE: pickle.load() from file."""
    with open(filepath, "rb") as f:
        obj = pickle.load(f)
    return obj


# ── Pattern 3: yaml.load with UnsafeLoader ─────────────────────────────────
def load_user_yaml(data: str):
    """VULNERABLE: yaml.load without SafeLoader."""
    obj = yaml.load(data)
    return obj


# ── SAFE versions (for contrast) ─────────────────────────────────────────────
def safe_load_session(data: bytes):
    """SAFE: use JSON instead of pickle."""
    import json
    return json.loads(data)


def safe_load_yaml(data: str):
    """SAFE: use yaml.safe_load."""
    return yaml.safe_load(data)
