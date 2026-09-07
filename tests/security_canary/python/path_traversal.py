#!/usr/bin/env python3
"""
Canary Test Suite: Path Traversal / Directory Traversal
========================================================
This file DELIBERATELY contains path traversal vulnerabilities.
It exists to validate that the scanner pipeline detects them.

Expected detections: CodeQL (python/path-injection), Semgrep, Bandit (B609/B604)
"""

import os
import subprocess


# ── Pattern 1: Path traversal via user input ─────────────────────────────────
def read_user_file(filename: str):
    """VULNERABLE: direct file read with user-controlled path."""
    filepath = f"/var/data/{filename}"
    with open(filepath, "r") as f:
        return f.read()


def read_file_vulnerable(user_path: str):
    """VULNERABLE: file read with user-controlled path."""
    return open(user_path).read()


# ── Pattern 2: Path traversal via subprocess ─────────────────────────────────
def execute_user_command_vulnerable(user_input: str):
    """VULNERABLE: subprocess with user-controlled filename."""
    return subprocess.check_output(f"cat {user_input}", shell=True)


# ── Pattern 3: Path traversal with os.path.join ──────────────────────────────
def get_user_document(base_dir: str, doc_name: str):
    """VULNERABLE: os.path.join doesn't prevent directory traversal."""
    full_path = os.path.join(base_dir, doc_name)
    return full_path


# ── SAFE versions (for contrast) ─────────────────────────────────────────────
def read_user_file_safe(base_dir: str, filename: str):
    """SAFE: validate path doesn't escape base directory."""
    safe_path = os.path.normpath(os.path.join(base_dir, filename))
    if not safe_path.startswith(os.path.realpath(base_dir)):
        raise ValueError("Path traversal detected")
    with open(safe_path, "r") as f:
        return f.read()


def get_user_document_safe(base_dir: str, doc_name: str):
    """SAFE: use pathlib with resolve and check."""
    from pathlib import Path
    base = Path(base_dir).resolve()
    target = (base / doc_name).resolve()
    if not str(target).startswith(str(base)):
        raise ValueError("Path traversal detected")
    return target
