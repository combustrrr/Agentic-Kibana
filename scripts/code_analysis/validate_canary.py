"""
Canary Validation Script
========================
Validates that the full analysis pipeline detects all expected vulnerabilities
in the canary test suite. Fails CI with a clear report if any go undetected.

Usage:
  python scripts/code_analysis/validate_canary.py --findings-dir ./normalized

This script is the INTEGRATION TEST for the entire tool web.
If it passes, the pipeline is coherent and has no unacknowledged dead spots.
"""

from __future__ import annotations

import json
import sys
from dataclasses import dataclass
from pathlib import Path

import click


# ─────────────────────────────────────────────────────────────────────────────
# Expected Detection Registry
# One entry per canary file — defines what MUST be detected and by WHOM
# ─────────────────────────────────────────────────────────────────────────────

@dataclass
class CanaryExpectation:
    file_suffix: str              # end of path — platform-independent
    concept: str                  # normalized vulnerability concept
    required_tools: list[str]     # these tools MUST each detect it
    min_detections: int           # at least N of the required_tools must trigger
    description: str              # human-readable name


EXPECTED_DETECTIONS: list[CanaryExpectation] = [
    # ── SQL Injection ────────────────────────────────────────────────────────
    CanaryExpectation(
        file_suffix="canary/python/sql_injection.py",
        concept="sql-injection",
        required_tools=["CodeQL", "Semgrep", "Bandit"],
        min_detections=2,
        description="SQL Injection (Python)",
    ),
    # ── Hardcoded Secret ─────────────────────────────────────────────────────
    CanaryExpectation(
        file_suffix="canary/python/hardcoded_secret.py",
        concept="hardcoded-secret",
        required_tools=["Bandit", "Gitleaks", "Semgrep"],
        min_detections=2,
        description="Hardcoded credentials / API key",
    ),
    # ── JWT None Algorithm ───────────────────────────────────────────────────
    CanaryExpectation(
        file_suffix="canary/python/jwt_none_algorithm.py",
        concept="jwt-none-alg",
        required_tools=["Semgrep"],   # custom rule — only Semgrep catches this
        min_detections=1,
        description="JWT 'none' algorithm attack",
    ),
    # ── Eval / Code Injection ────────────────────────────────────────────────
    CanaryExpectation(
        file_suffix="canary/python/eval_exec.py",
        concept="code-injection",
        required_tools=["Bandit", "Semgrep"],
        min_detections=2,
        description="eval() / exec() code injection",
    ),
    # ── Pickle Deserialization ───────────────────────────────────────────────
    CanaryExpectation(
        file_suffix="canary/python/pickle_deserialization.py",
        concept="unsafe-deserialization",
        required_tools=["Bandit", "Semgrep"],
        min_detections=1,
        description="Unsafe pickle deserialization",
    ),
    # ── Path Traversal ───────────────────────────────────────────────────────
    CanaryExpectation(
        file_suffix="canary/python/path_traversal.py",
        concept="path-traversal",
        required_tools=["CodeQL", "Semgrep", "Bandit"],
        min_detections=1,
        description="Path traversal / directory traversal",
    ),
    # ── Prompt Injection (LangGraph) ─────────────────────────────────────────
    CanaryExpectation(
        file_suffix="canary/python/prompt_injection.py",
        concept="code-injection",
        required_tools=["Semgrep"],   # custom rule catches this
        min_detections=1,
        description="LLM output used in eval() (prompt injection → RCE)",
    ),
    # ── XSS (TypeScript/React) ───────────────────────────────────────────────
    CanaryExpectation(
        file_suffix="canary/typescript/xss_dangerously.tsx",
        concept="xss",
        required_tools=["ESLint", "CodeQL", "Semgrep"],
        min_detections=1,
        description="XSS via dangerouslySetInnerHTML (React)",
    ),
    # ── Dockerfile root user ─────────────────────────────────────────────────
    CanaryExpectation(
        file_suffix="canary/Dockerfile.insecure",
        concept="dockerfile-root",
        required_tools=["Hadolint", "Checkov"],
        min_detections=1,
        description="Dockerfile runs as root",
    ),
    # ── Vulnerable dependency ────────────────────────────────────────────────
    CanaryExpectation(
        file_suffix="canary-input/requirements-vulnerable.txt",
        concept="dependency-vuln",
        required_tools=["OSV-Scanner", "Snyk"],
        min_detections=1,
        description="Known-vulnerable Python package version",
    ),
]


# ─────────────────────────────────────────────────────────────────────────────
# Validation Logic
# ─────────────────────────────────────────────────────────────────────────────

def load_findings(findings_dir: Path) -> list[dict]:
    """Load the normalizer's unified findings output."""
    findings_file = findings_dir / "unified-findings.json"
    if not findings_file.exists():
        print(f"[ERROR] Findings file not found: {findings_file}")
        sys.exit(2)
    with findings_file.open() as f:
        return json.load(f)


def validate(findings: list[dict], expectation: CanaryExpectation) -> tuple[bool, str]:
    """
    Check if a specific canary expectation is met.
    Returns (passed, error_message).
    """
    relevant = [
        f for f in findings
        if expectation.file_suffix in f.get("file", "")
        and f.get("rule_concept") == expectation.concept
    ]

    if not relevant:
        return False, (
            f"[MISS] No tool detected '{expectation.concept}' "
            f"in '{expectation.file_suffix}'\n"
            f"  Required: {expectation.min_detections} of {expectation.required_tools}"
        )

    detected_tools = {f.get("source_tool", "") for f in relevant}
    required_set = set(expectation.required_tools)
    intersection = detected_tools & required_set
    detected_count = len(intersection)

    if detected_count < expectation.min_detections:
        return False, (
            f"[PARTIAL MISS] '{expectation.description}' in '{expectation.file_suffix}'\n"
            f"  Concept: {expectation.concept}\n"
            f"  Detected by: {intersection}\n"
            f"  Required at least {expectation.min_detections} of: {required_set}\n"
            f"  These tools MISSED it: {required_set - intersection}"
        )

    return True, (
        f"[PASS] {expectation.description}\n"
        f"   Detected by: {intersection} (needed {expectation.min_detections})"
    )


@click.command()
@click.option(
    "--findings-dir", "-d",
    type=click.Path(exists=True),
    default="./normalized",
    help="Directory containing normalizer output",
)
@click.option("--verbose", "-v", is_flag=True)
def main(findings_dir: str, verbose: bool) -> None:
    """
    Validate that all canary vulnerabilities are detected by the pipeline.

    This is the integration test for the entire tool web.
    Exits with code 1 if any expected vulnerability is missed.
    """
    findings_path = Path(findings_dir)
    findings = load_findings(findings_path)

    print(f"\n{'='*60}")
    print(" Canary Coverage Validation")
    print(f"{'='*60}")
    print(f"   Loaded {len(findings)} findings from {findings_dir}")
    print(f"   Checking {len(EXPECTED_DETECTIONS)} canary expectations\n")

    passed: list[str] = []
    failed: list[str] = []

    for expectation in EXPECTED_DETECTIONS:
        ok, message = validate(findings, expectation)
        if ok:
            passed.append(message)
            if verbose:
                print(f"  {message}")
        else:
            failed.append(message)
            print(f"  {message}")

    print(f"\n{'-' * 60}")
    print(f"Results: {len(passed)}/{len(EXPECTED_DETECTIONS)} expectations met")

    if failed:
        print(f"\n[FAIL] {len(failed)} COVERAGE GAPS DETECTED:\n")
        for msg in failed:
            print(f"  {msg}\n")
        print("-" * 60)
        print("ACTION REQUIRED:")
        print("  1. Check if the tool is running and its config is correct")
        print("  2. Verify the canary file has not been modified (it should be vulnerable)")
        print("  3. If the gap is known and accepted, add it to ACKNOWLEDGED_GAPS")
        print("  4. Update the CONCEPT_MAP in normalizer.py if it's a mapping issue")
        sys.exit(1)

    else:
        print(f"\n[PASS] All {len(EXPECTED_DETECTIONS)} canary vulnerabilities detected!")
        print("   The tool pipeline is coherent and has no unacknowledged dead spots.")
        sys.exit(0)


if __name__ == "__main__":
    main()
