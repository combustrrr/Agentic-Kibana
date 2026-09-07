#!/usr/bin/env python3
"""
Canary Test Suite: eval() / exec() Code Injection
===================================================
This file DELIBERATELY contains dangerous code execution patterns.
It exists to validate that the scanner pipeline detects them.

Expected detections: Bandit (B307), Semgrep
"""

import subprocess
import os


# ── Pattern 1: eval() with user input ────────────────────────────────────────
def process_user_code(code: str):
    """VULNERABLE: eval() on user-controlled input."""
    result = eval(code)
    return result


# ── Pattern 2: exec() with user input ────────────────────────────────────────
def execute_user_script(script: str):
    """VULNERABLE: exec() on user-controlled input."""
    exec(script)


# ── Pattern 3: subprocess with shell=True and user input ────────────────────
def run_user_command(cmd: str):
    """VULNERABLE: subprocess with shell=True and user input."""
    result = subprocess.run(f"echo {cmd}", shell=True, capture_output=True, text=True)
    return result.stdout


# ── Pattern 4: os.system with user input ────────────────────────────────────
def system_user_input(user_input: str):
    """VULNERABLE: os.system with user-controlled input."""
    os.system(f"ping {user_input}")


# ── SAFE versions (for contrast) ─────────────────────────────────────────────
def safe_process_data(data: str):
    """SAFE: no eval/exec; parse with json or a safe parser."""
    import json
    return json.loads(data)


def safe_run_command(args: list[str]):
    """SAFE: subprocess with shell=False and argument list."""
    return subprocess.run(args, shell=False, capture_output=True, text=True)
