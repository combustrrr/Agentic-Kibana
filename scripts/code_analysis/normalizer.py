#!/usr/bin/env python3
"""
Finding Normalizer — Agentic SOC static-analysis monitoring
================================================================
Ingests tool outputs (SARIF, Bandit JSON, Ruff JSON) and normalizes them
into a unified finding schema with deterministic deduplication.

Supports:
  - SARIF (CodeQL, Semgrep, Trivy, Hadolint, Qodana, OSV-Scanner, Checkov)
  - Bandit JSON
  - Ruff JSON
  - Vulture JSON
  - Pyright JSON

Outputs:
  - unified-findings.json        (all findings, raw)
  - deduplicated-findings.json   (canonical findings only, duplicates removed)
  - normalized.sarif             (re-exported SARIF for GitHub Security tab)

Usage:
  python scripts/code_analysis/normalizer.py --input-dir ./scan-results --output-dir ./normalized

Requirements:
  pip install click
"""

from __future__ import annotations

import hashlib
import json
import os
import re
import sys
import xml.etree.ElementTree as ET
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any

import click

try:
    from rich.console import Console
    console = Console()
except ImportError:
    console = None


REPOSITORY_ROOTS = (".github", "backend", "docs", "scripts", "webui")


def canonicalize_file(raw_path: str) -> str:
    """Return a stable repository-relative path for cross-run fingerprints."""
    value = str(raw_path or "").replace("\\", "/")
    if value.startswith("file://"):
        value = value.removeprefix("file://").lstrip("/")
    workspace = os.environ.get("GITHUB_WORKSPACE", "").replace("\\", "/").rstrip("/")
    if workspace and value.lower().startswith(f"{workspace.lower()}/"):
        value = value[len(workspace) + 1:]
    value = value.removeprefix("./")
    if ":/" in value or value.startswith("/"):
        candidates = [value.find(f"/{root}/") + 1 for root in REPOSITORY_ROOTS
                      if value.find(f"/{root}/") >= 0]
        if candidates:
            value = value[min(candidates):]
    return value


# ─────────────────────────────────────────────────────────────
# Concept Normalization Map
# Maps tool-specific rule IDs → canonical vulnerability concept.
# The same vulnerability found by CodeQL AND Semgrep at the
# same file+line gets the SAME fingerprint → deduplicated to ONE finding.
# ─────────────────────────────────────────────────────────────

CONCEPT_MAP: dict[str, str] = {
    # ── SQL Injection ─────────────────────────────────────────
    "python/sql-injection":                      "sql-injection",
    "python/sql-injection-local":                "sql-injection",
    "python.sqlalchemy.security.sqlalchemy-execute-injection": "sql-injection",
    "python.fastapi.security.fastapi-sqli":      "sql-injection",
    "kavach-sqlalchemy-raw-string-execute":      "sql-injection",
    "kavach-aiosqlite-raw-string-execute":       "sql-injection",
    "B608":                                      "sql-injection",  # Bandit
    "sql-injection":                             "sql-injection",
    "S608":                                      "sql-injection",  # Ruff
    "agentic-soc-sql-string-construction":       "sql-injection",

    # ── XSS ───────────────────────────────────────────────────
    "python/reflected-xss":                      "xss",
    "python/stored-xss":                         "xss",
    "javascript/xss":                            "xss",
    "js/xss":                                    "xss",
    "js/xss-through-dom":                        "xss",
    "javascript/dom-based-xss":                  "xss",
    "react/no-danger":                           "xss",            # ESLint
    "no-dangerouslysetinnterhtml":               "xss",
    "agentic-soc-react-unsanitized-html":        "xss",

    # ── Path Traversal ────────────────────────────────────────
    "python/path-injection":                     "path-traversal",
    "python.lang.security.audit.path-traversal": "path-traversal",
    "B609":                                      "path-traversal",
    "B604":                                      "path-traversal",
    "agentic-soc-unvalidated-file-path":         "path-traversal",

    # ── Hardcoded Secrets / Credentials ──────────────────────
    "HardcodedPassword":                         "hardcoded-secret",
    "HardcodedSecret":                           "hardcoded-secret",
    "B105":                                      "hardcoded-secret",
    "B106":                                      "hardcoded-secret",
    "B107":                                      "hardcoded-secret",
    "python.lang.security.hardcoded-token":      "hardcoded-secret",
    "kavach-hardcoded-api-key":                  "hardcoded-secret",  # custom
    "kavach-hardcoded-password":                 "hardcoded-secret",
    "kavach-jwt-secret":                        "hardcoded-secret",
    "kavach-openai-key":                        "hardcoded-secret",
    "kavach-anthropic-key":                     "hardcoded-secret",
    "kavach-google-api-key":                    "hardcoded-secret",
    "kavach-oauth-client-secret":               "hardcoded-secret",
    "kavach-totp-secret":                       "hardcoded-secret",
    "kavach-db-password":                       "hardcoded-secret",
    "kavach-generic-api-key":                   "hardcoded-secret",
    "S105":                                      "hardcoded-secret",  # Ruff
    "S106":                                      "hardcoded-secret",
    "S107":                                      "hardcoded-secret",

    # ── Eval / Code Injection ────────────────────────────────
    "python/code-injection":                     "code-injection",
    "python.lang.security.dangerous-eval":       "code-injection",
    "B307":                                      "code-injection",
    "kavach-llm-output-exec-injection":          "code-injection",   # custom
    "kavach-dangerous-eval-exec":                "code-injection",
    "S307":                                      "code-injection",

    # ── Deserialization ───────────────────────────────────────
    "python/unsafe-deserialization":             "unsafe-deserialization",
    "python.lang.security.insecure-pickle":      "unsafe-deserialization",
    "B301":                                      "unsafe-deserialization",
    "B302":                                      "unsafe-deserialization",
    "kavach-pickle-deserialization":             "unsafe-deserialization",

    # ── JWT Attacks ───────────────────────────────────────────
    "python/jwt-missing-verification":           "jwt-none-alg",
    "python.jwt.security.jwt-none-algorithm":    "jwt-none-alg",
    "kavach-jwt-decode-no-algorithm":            "jwt-none-alg",     # custom
    "kavach-jwt-hardcoded-secret":               "jwt-weak-secret",  # custom

    # ── Prompt Injection / Agent Safety ──────────────────────
    "kavach-langgraph-unrestricted-tool-invocation": "agent-tool-injection",
    "kavach-unsanitized-llm-output-in-http-response":  "prompt-injection-reflect",

    # ── SSRF ─────────────────────────────────────────────────
    "python/ssrf":                               "ssrf",
    "python.requests.security.ssrf":             "ssrf",
    "B310":                                      "ssrf",

    # ── Subprocess / Command Injection ────────────────────────
    "python/shell-command-injection":            "command-injection",
    "python.lang.security.dangerous-subproc":    "command-injection",
    "B602":                                      "command-injection",
    "B603":                                      "command-injection",
    "B605":                                      "command-injection",
    "S603":                                      "command-injection",
    "kavach-subprocess-shell-true":              "command-injection",

    # ── Insecure Crypto / Hashing ────────────────────────────
    "python/weak-cryptography":                  "weak-crypto",
    "python.lang.security.insecure-hash":        "weak-crypto",
    "B303":                                      "weak-crypto",
    "B324":                                      "weak-crypto",
    "InsecureHashUsage":                         "weak-crypto",
    "kavach-weak-crypto-hash":                   "weak-crypto",

    # ── CORS ─────────────────────────────────────────────────
    "kavach-cors-wildcard":                      "cors-wildcard",

    # ── Missing Auth ─────────────────────────────────────────
    "kavach-fastapi-missing-security-dependency": "missing-auth",

    # ── Elasticsearch Injection ─────────────────────────────
    "kavach-elasticsearch-query-injection":      "es-query-injection",

    # ── Container / IaC ──────────────────────────────────────
    "DL3002":                                  "dockerfile-root",   # Hadolint
    "DL3006":                                  "dockerfile-no-tag",
    "DL3008":                                  "dockerfile-pin",
    "CKV_DOCKER_3":                            "dockerfile-root",   # Checkov non-root user
    "CKV_DOCKER_2":                            "dockerfile-healthcheck",
    "CKV_GHA_1":                               "gha-pin-actions",
    "kavach-debug-mode-enabled":               "debug-mode-enabled",

    # ── Active Fuzzing ──────────────────────────────────────
    "schemathesis.api.500":                    "api-500-crash",
    "atheris.state.exception":                 "unhandled-state-exception",

    # ── Dependency vulnerabilities ─────────────────────────
    "dependency-vuln":                         "dependency-vuln",
}


def normalize_concept(rule_id: str, message: str = "") -> str:
    """Map a tool-specific rule ID to a canonical vulnerability concept."""
    if rule_id in CONCEPT_MAP:
        return CONCEPT_MAP[rule_id]
    # Prefix/suffix match for compound IDs
    for key, concept in CONCEPT_MAP.items():
        if rule_id.lower().endswith(key.lower()) or rule_id.lower().startswith(key.lower()):
            return concept
    # Fallback: lowercase rule ID is its own concept
    return rule_id.lower().replace(":", "-").replace("/", "-")


# ─────────────────────────────────────────────────────────────
# Unified Finding Schema
# ─────────────────────────────────────────────────────────────

@dataclass
class Finding:
    """Unified, normalized finding from any analysis tool."""

    # Identity
    id: str = ""              # Stable fingerprint: SHA256(file+line+concept)
    source_tool: str = ""     # e.g., "CodeQL", "Semgrep", "Ruff"

    # Classification
    category: str = ""        # SECURITY | QUALITY | DEAD_CODE | COMPLEXITY | DEPENDENCY | SECRET
    severity: str = ""        # CRITICAL | HIGH | MEDIUM | LOW | INFO
    confidence: str = ""      # HIGH | MEDIUM | LOW

    # Location
    file: str = ""
    start_line: int = 0
    end_line: int = 0
    start_col: int = 0
    end_col: int = 0
    code_snippet: str = ""

    # Rule
    rule_id: str = ""         # Original tool rule ID
    rule_concept: str = ""    # Canonical concept — used for fingerprint
    rule_name: str = ""
    message: str = ""
    description: str = ""

    # Standards mapping
    cwe: list[str] = field(default_factory=list)
    owasp: list[str] = field(default_factory=list)
    cvss_score: float = 0.0

    # Context
    commit: str = ""
    pr_number: str = ""
    branch: str = ""

    # Native scanner provenance retained by the current-snapshot platform.
    native_result_id: str = ""
    analysis_category: str = ""
    tool_version: str = ""
    ruleset_version: str = ""
    raw_artifact: str = ""

    # Analysis metadata
    reachability: str = ""
    exploitability: str = ""
    duplicate_group: str = ""
    is_duplicate: bool = False

    # Remediation
    suggested_fix: str = ""
    fix_guidance: str = ""
    auto_fixable: bool = False
    fix_level: int = 0       # 0=manual | 1=safe-autofix | 2=ai-patch

    # Lifecycle — State Machine
    validation_status: str = "NEW"
    evidence: list[str] = field(default_factory=list)
    first_seen: str = ""
    last_seen: str = ""
    consecutive_clean_scans: int = 0

    # Tags
    tags: list[str] = field(default_factory=list)

    def compute_id(self) -> str:
        """
        Stable fingerprint based on LOCATION + CONCEPT (not tool or rule ID).
        The same vulnerability found by CodeQL, Semgrep, and Bandit at the
        same file+line gets the SAME fingerprint → deduplicated to ONE issue.
        """
        key = self.dedup_key()
        return hashlib.sha256(key.encode()).hexdigest()[:16]

    def __post_init__(self) -> None:
        import datetime
        now = datetime.datetime.utcnow().isoformat()
        self.file = canonicalize_file(self.file)
        if not self.rule_concept:
            self.rule_concept = normalize_concept(self.rule_id)
        if not self.id:
            self.id = self.compute_id()
        if not self.first_seen:
            self.first_seen = now
        if not self.last_seen:
            self.last_seen = now

    def dedup_key(self) -> str:
        """Conservative cross-tool key; never collapse on file+line alone."""
        concept = self.rule_concept or normalize_concept(self.rule_id)
        snippet = re.sub(r"\s+", " ", self.code_snippet.strip())
        if snippet:
            column = (f":column:{self.start_col}:{self.end_col or self.start_col}"
                      if self.start_col else "")
            anchor = f"snippet:{snippet}{column}"
        elif self.start_col:
            anchor = f"column:{self.start_col}:{self.end_col or self.start_col}"
        elif self.native_result_id or self.id:
            anchor = f"native:{self.source_tool}:{self.native_result_id or self.id}"
        else:
            message = re.sub(r"\s+", " ", self.message.strip())
            anchor = f"fallback:{self.source_tool}:{self.rule_id}:{message}"
        return f"{canonicalize_file(self.file)}:{self.start_line}:{concept}:{anchor}"


# ─────────────────────────────────────────────────────────────
# Severity / Category normalization
# ─────────────────────────────────────────────────────────────

_SEVERITY_MAP: dict[str, str] = {
    "error": "HIGH",        # SARIF
    "warning": "MEDIUM",
    "note": "LOW",
    "none": "INFO",
    "critical": "CRITICAL",
    "high": "HIGH",
    "medium": "MEDIUM",
    "low": "LOW",
    "info": "INFO",
    "informational": "INFO",
    "recommendation": "LOW",  # CodeQL
}


def normalize_severity(raw: str) -> str:
    return _SEVERITY_MAP.get(raw.lower(), "MEDIUM")


_CATEGORY_MAP: dict[str, str] = {
    "security": "SECURITY",
    "vulnerability": "SECURITY",
    "secret": "SECRET",
    "dead_code": "DEAD_CODE",
    "complexity": "COMPLEXITY",
    "quality": "QUALITY",
    "dependency": "DEPENDENCY",
    "style": "QUALITY",
    "correctness": "QUALITY",
}


def normalize_category(tool: str, rule_id: str, tags: list[str]) -> str:
    for tag in tags:
        if tag.lower() in _CATEGORY_MAP:
            return _CATEGORY_MAP[tag.lower()]
    if tool in ("Gitleaks", "detect-secrets"):
        return "SECRET"
    if tool in ("OSV-Scanner", "Trivy-SCA"):
        return "DEPENDENCY"
    if tool in ("Vulture", "Coverage.py"):
        return "DEAD_CODE"
    if tool in ("Radon", "Xenon"):
        return "COMPLEXITY"
    if tool in ("CodeQL", "Semgrep", "Bandit", "Qodana"):
        return "SECURITY"
    prefix = rule_id[:1].upper()
    if prefix == "S":
        return "SECURITY"
    return "QUALITY"


# ─────────────────────────────────────────────────────────────
# Parsers — one per tool format
# ─────────────────────────────────────────────────────────────

class SarifParser:
    """Parses SARIF 2.1 format (CodeQL, Semgrep, Trivy, Hadolint, Qodana, OSV)."""

    TOOL_NAME_MAP: dict[str, str] = {
        "codeql": "CodeQL",
        "semgrep": "Semgrep",
        "trivy": "Trivy",
        "hadolint": "Hadolint",
        "gitleaks": "Gitleaks",
        "qodana": "Qodana",
        "osv-scanner": "OSV-Scanner",
        "checkov": "Checkov",
    }

    def parse(self, sarif_path: Path, tool_hint: str = "") -> list[Finding]:
        findings: list[Finding] = []
        with sarif_path.open() as f:
            sarif = json.load(f)

        for run in sarif.get("runs", []):
            driver = run.get("tool", {}).get("driver", {})
            raw_tool = driver.get("name", tool_hint)
            tool_name = self.TOOL_NAME_MAP.get(raw_tool.lower(), raw_tool)

            rules: dict[str, dict[str, Any]] = {
                r["id"]: r for r in driver.get("rules", [])
            }

            for result in run.get("results", []):
                rule_id = result.get("ruleId", "")
                rule = rules.get(rule_id, {})

                msg = (
                    result.get("message", {}).get("text", "")
                    or rule.get("shortDescription", {}).get("text", "")
                )

                level = result.get("level", "warning")
                rule_level = rule.get("defaultConfiguration", {}).get("level", level)
                severity = normalize_severity(rule_level)

                locations = result.get("locations", [])
                file_path = ""
                start_line = 0
                end_line = 0
                start_col = 0
                end_col = 0
                snippet = ""

                if locations:
                    phys = locations[0].get("physicalLocation", {})
                    art = phys.get("artifactLocation", {})
                    file_path = art.get("uri", "").replace("file:///", "").replace("file://", "")
                    region = phys.get("region", {})
                    start_line = region.get("startLine", 0)
                    end_line = region.get("endLine", start_line)
                    start_col = region.get("startColumn", 0)
                    end_col = region.get("endColumn", 0)
                    snippet = region.get("snippet", {}).get("text", "")

                tags = rule.get("properties", {}).get("tags", [])
                cwes = [t for t in tags if t.startswith("CWE-")]
                owasps = [t for t in tags if "OWASP" in t or t.startswith("A0")]

                category = normalize_category(tool_name, rule_id, tags)
                finding = Finding(
                    source_tool=tool_name,
                    category=category,
                    severity=severity,
                    confidence="HIGH" if tool_name in ("CodeQL",) else "MEDIUM",
                    file=file_path,
                    start_line=start_line,
                    end_line=end_line,
                    start_col=start_col,
                    end_col=end_col,
                    code_snippet=snippet,
                    rule_id=rule_id,
                    rule_name=rule.get("name", rule_id),
                    message=msg,
                    description=rule.get("fullDescription", {}).get("text", ""),
                    cwe=cwes,
                    owasp=owasps,
                    tags=tags,
                    rule_concept="dependency-vuln" if tool_name == "OSV-Scanner" else "",
                    native_result_id=str(result.get("guid") or result.get("fingerprints", {}).get("primaryLocationLineHash") or ""),
                    analysis_category=str(run.get("automationDetails", {}).get("id") or ""),
                    tool_version=str(driver.get("semanticVersion") or driver.get("version") or ""),
                )
                findings.append(finding)

        return findings


class BanditParser:
    """Parses Bandit JSON output."""

    def parse(self, bandit_path: Path) -> list[Finding]:
        with bandit_path.open() as f:
            data = json.load(f)

        findings: list[Finding] = []
        for result in data.get("results", []):
            severity = normalize_severity(result.get("issue_severity", "medium"))
            confidence = result.get("issue_confidence", "medium").upper()
            cwe_raw = result.get("issue_cwe", {})
            cwe = [f"CWE-{cwe_raw.get('id', '')}"] if cwe_raw else []

            finding = Finding(
                source_tool="Bandit",
                category="SECURITY",
                severity=severity,
                confidence=confidence,
                file=result.get("filename", ""),
                start_line=result.get("line_number", 0),
                end_line=result.get("line_range", [0])[-1] if result.get("line_range") else 0,
                code_snippet=result.get("code", ""),
                rule_id=result.get("test_id", ""),
                rule_name=result.get("test_name", ""),
                message=result.get("issue_text", ""),
                cwe=cwe,
                tags=["security"],
            )
            findings.append(finding)

        return findings


class RuffParser:
    """Parses Ruff JSON output."""

    _SECURITY_PREFIXES = {"S", "B"}

    def parse(self, ruff_path: Path) -> list[Finding]:
        with ruff_path.open() as f:
            data = json.load(f)

        findings: list[Finding] = []
        for result in data:
            code = result.get("code", "")
            prefix = code[:1]
            is_security = prefix in self._SECURITY_PREFIXES
            category = "SECURITY" if is_security else "QUALITY"
            severity = "HIGH" if is_security else "LOW"
            fix = result.get("fix")

            finding = Finding(
                source_tool="Ruff",
                category=category,
                severity=severity,
                confidence="HIGH",
                file=result.get("filename", ""),
                start_line=result.get("location", {}).get("row", 0),
                end_line=result.get("end_location", {}).get("row", 0),
                start_col=result.get("location", {}).get("column", 0),
                rule_id=code,
                rule_name=result.get("message", ""),
                message=result.get("message", ""),
                suggested_fix=fix.get("message", "") if fix else "",
                auto_fixable=fix is not None,
                fix_level=1 if fix else 0,
            )
            findings.append(finding)

        return findings


class VultureParser:
    """Parses Vulture JSON output."""

    def parse(self, vulture_path: Path) -> list[Finding]:
        with vulture_path.open() as f:
            data = json.load(f)

        findings: list[Finding] = []
        for result in data:
            finding = Finding(
                source_tool="Vulture",
                category="DEAD_CODE",
                severity="LOW",
                confidence=result.get("confidence", 0.8) and "HIGH" or "LOW",
                file=result.get("file", ""),
                start_line=result.get("line", 0),
                end_line=result.get("line", 0),
                rule_id="dead-code",
                rule_name=result.get("description", ""),
                message=result.get("description", ""),
                tags=["dead_code"],
            )
            findings.append(finding)

        return findings

    def parse_text(self, vulture_path: Path) -> list[Finding]:
        """Parse Vulture's default ``file:line: message (confidence%)`` output."""
        findings: list[Finding] = []
        pattern = re.compile(r"^(.*?):(\d+):\s*(.*?)\s*\((\d+)% confidence\)\s*$")
        for raw_line in vulture_path.read_text(encoding="utf-8", errors="replace").splitlines():
            match = pattern.match(raw_line)
            if not match:
                continue
            file_name, line, message, confidence = match.groups()
            findings.append(Finding(
                source_tool="Vulture", category="DEAD_CODE", severity="LOW",
                confidence="HIGH" if int(confidence) >= 90 else "MEDIUM",
                file=file_name, start_line=int(line), end_line=int(line),
                rule_id="dead-code", rule_name="Potential dead code", message=message,
                tags=["dead_code"],
            ))
        return findings


class SemgrepParser:
    """Parses Semgrep JSON output."""

    def parse(self, path: Path) -> list[Finding]:
        data = json.loads(path.read_text(encoding="utf-8"))
        findings = []
        for result in data.get("results", []):
            extra = result.get("extra", {})
            metadata = extra.get("metadata", {}) or {}
            raw_cwe = metadata.get("cwe", [])
            raw_owasp = metadata.get("owasp", [])
            cwe = [str(raw_cwe)] if isinstance(raw_cwe, str) else [str(v) for v in raw_cwe]
            owasp = [str(raw_owasp)] if isinstance(raw_owasp, str) else [str(v) for v in raw_owasp]
            severity = normalize_severity(str(extra.get("severity", "WARNING")))
            rule_id = str(result.get("check_id", ""))
            tags = ["security", *cwe, *owasp]
            findings.append(Finding(
                source_tool="Semgrep", category=normalize_category("Semgrep", rule_id, tags),
                severity=severity, confidence=str(metadata.get("confidence", "MEDIUM")).upper(),
                file=result.get("path", ""), start_line=result.get("start", {}).get("line", 0),
                end_line=result.get("end", {}).get("line", 0), start_col=result.get("start", {}).get("col", 0),
                end_col=result.get("end", {}).get("col", 0), rule_id=rule_id, rule_name=rule_id,
                message=extra.get("message", ""), cwe=cwe, owasp=owasp, tags=tags,
                suggested_fix=extra.get("fix", ""), auto_fixable=bool(extra.get("fix")),
                fix_level=1 if extra.get("fix") else 0,
            ))
        return findings


class PyrightParser:
    """Parses Pyright ``--outputjson`` diagnostics."""

    def parse(self, path: Path) -> list[Finding]:
        data = json.loads(path.read_text(encoding="utf-8"))
        findings = []
        for result in data.get("generalDiagnostics", []):
            span = result.get("range", {})
            start, end = span.get("start", {}), span.get("end", {})
            severity = {"error": "HIGH", "warning": "MEDIUM", "information": "LOW"}.get(
                str(result.get("severity", "warning")).lower(), "MEDIUM")
            findings.append(Finding(
                source_tool="Pyright", category="QUALITY", severity=severity, confidence="HIGH",
                file=result.get("file", ""), start_line=int(start.get("line", 0)) + 1,
                end_line=int(end.get("line", 0)) + 1, start_col=int(start.get("character", 0)) + 1,
                end_col=int(end.get("character", 0)) + 1, rule_id=result.get("rule") or "type-check",
                rule_name=result.get("rule") or "Type checking", message=result.get("message", ""),
                tags=["quality", "type-checking"],
            ))
        return findings


class EslintParser:
    """Parses ESLint JSON output."""

    def parse(self, path: Path) -> list[Finding]:
        data = json.loads(path.read_text(encoding="utf-8"))
        findings = []
        for report in data:
            for result in report.get("messages", []):
                severity = "HIGH" if result.get("severity") == 2 else "MEDIUM"
                fix = result.get("fix")
                findings.append(Finding(
                    source_tool="ESLint", category="QUALITY", severity=severity, confidence="HIGH",
                    file=report.get("filePath", ""), start_line=result.get("line", 0),
                    end_line=result.get("endLine") or result.get("line", 0), start_col=result.get("column", 0),
                    end_col=result.get("endColumn", 0), rule_id=result.get("ruleId") or "eslint",
                    rule_name=result.get("ruleId") or "ESLint", message=result.get("message", ""),
                    auto_fixable=bool(fix), fix_level=1 if fix else 0, tags=["quality"],
                ))
        return findings


class TscParser:
    """Parse stable ``tsc --pretty false`` diagnostics."""

    _PATTERN = re.compile(r"^(.*)\((\d+),(\d+)\):\s+(error|warning)\s+(TS\d+):\s+(.*)$")

    def parse(self, path: Path) -> list[Finding]:
        findings: list[Finding] = []
        for line in path.read_text(encoding="utf-8", errors="replace").splitlines():
            match = self._PATTERN.match(line.strip())
            if not match:
                continue
            file_name, row, column, level, rule, message = match.groups()
            findings.append(Finding(
                source_tool="TypeScript", category="QUALITY",
                severity="HIGH" if level == "error" else "MEDIUM", confidence="HIGH",
                file=file_name, start_line=int(row), end_line=int(row), start_col=int(column),
                rule_id=rule, rule_name="TypeScript compiler diagnostic", message=message,
                tags=["quality", "type-checking"],
            ))
        return findings


class XenonParser:
    """Parse Xenon's stable advisory text into structured complexity findings."""

    _LOCATION = re.compile(r"(?P<file>[^\s:'\"]+\.py)(?::(?P<line>\d+))?")

    def parse(self, path: Path) -> list[Finding]:
        findings: list[Finding] = []
        for raw_line in path.read_text(encoding="utf-8", errors="replace").splitlines():
            line = raw_line.strip()
            if "xenon" not in line.lower() or not any(word in line.lower() for word in ("error", "warning")):
                continue
            location = self._LOCATION.search(line)
            file_name = location.group("file") if location else "backend"
            row = int(location.group("line") or 0) if location else 0
            rank = re.search(r"rank\s+([A-F])|grade\s+([A-F])|\b([D-F])\b", line, re.IGNORECASE)
            grade = next((value for value in rank.groups() if value), "C").upper() if rank else "C"
            severity = "HIGH" if grade in {"E", "F"} else "MEDIUM"
            findings.append(Finding(
                source_tool="Xenon", category="COMPLEXITY", severity=severity, confidence="HIGH",
                file=file_name, start_line=row, end_line=row, rule_id=f"xenon-rank-{grade.lower()}",
                rule_name="Cyclomatic complexity threshold", message=line,
                tags=["complexity", "maintainability"],
            ))
        return findings

# ─────────────────────────────────────────────────────────────
# Deduplication
# ─────────────────────────────────────────────────────────────

class RadonParser:
    """Turn Radon rank B-F blocks into file/symbol complexity findings."""

    def parse(self, path: Path) -> list[Finding]:
        report = json.loads(path.read_text(encoding="utf-8"))
        findings: list[Finding] = []

        def retain(file_name: str, block: dict) -> None:
            rank = str(block.get("rank") or "A").upper()
            if rank not in {"B", "C", "D", "E", "F"}:
                return
            line = int(block.get("lineno") or 0)
            name = str(block.get("fullname") or block.get("name") or "<module>")
            complexity = int(block.get("complexity") or 0)
            findings.append(Finding(
                source_tool="Radon", category="COMPLEXITY",
                severity="HIGH" if rank in {"E", "F"} else "MEDIUM",
                confidence="HIGH", file=file_name, start_line=line,
                end_line=int(block.get("endline") or line),
                rule_id=f"radon-rank-{rank.lower()}",
                rule_name="Cyclomatic complexity",
                message=f"{name} has cyclomatic complexity {complexity} (rank {rank})",
                tags=["complexity", "maintainability"],
            ))
            for child in (block.get("methods") or []) + (block.get("closures") or []):
                retain(file_name, child)

        if not isinstance(report, dict):
            raise ValueError("Radon report must be an object keyed by source path")
        for file_name, blocks in report.items():
            if not isinstance(blocks, list):
                raise ValueError(f"Radon blocks must be an array: {file_name}")
            for block in blocks:
                retain(file_name, block)
        return findings


class CoverageParser:
    """Represent every file-level executable-line coverage gap as one finding."""

    def parse(self, path: Path) -> list[Finding]:
        report = json.loads(path.read_text(encoding="utf-8"))
        files = report.get("files")
        if not isinstance(files, dict):
            raise ValueError("Coverage.py report is missing the files object")
        findings: list[Finding] = []
        for file_name, detail in files.items():
            if file_name.startswith(("app/", "tests/")):
                file_name = f"backend/{file_name}"
            missing = detail.get("missing_lines") or []
            if not missing:
                continue
            summary = detail.get("summary") or {}
            percent = float(summary.get("percent_covered") or 0.0)
            first_line = int(missing[0])
            findings.append(Finding(
                source_tool="Coverage.py", category="COVERAGE",
                severity="MEDIUM" if percent < 50 else "LOW", confidence="HIGH",
                file=file_name, start_line=first_line, end_line=int(missing[-1]),
                rule_id="coverage-missing-lines", rule_name="Executable lines not covered",
                message=(f"{len(missing)} executable lines are not covered; "
                         f"file coverage is {percent:.2f}%"),
                tags=["coverage", "runtime-evidence"],
            ))
        return findings


class SchemathesisParser:
    """Convert Schemathesis JUnit failures into structured dynamic findings."""

    def parse(self, path: Path) -> list[Finding]:
        root = ET.parse(path).getroot()
        findings: list[Finding] = []
        for case in root.iter("testcase"):
            failures = [*case.findall("failure"), *case.findall("error")]
            for index, failure in enumerate(failures, start=1):
                message = "\n".join(filter(None, [failure.get("message"), failure.text])).strip()
                lowered = message.lower()
                concept = "api-500-crash" if any(token in lowered for token in (
                    "status code: 500", "status_code=500", "internal server error")) else "api-contract-failure"
                endpoint = case.get("name") or case.get("classname") or "OpenAPI operation"
                findings.append(Finding(
                    source_tool="Schemathesis", category="DYNAMIC",
                    severity="HIGH" if concept == "api-500-crash" else "MEDIUM",
                    confidence="HIGH", file="backend/openapi", start_line=0, end_line=0,
                    rule_id=f"schemathesis.{concept}", rule_concept=concept,
                    rule_name="Schemathesis API property failure", message=message or endpoint,
                    native_result_id=f"{endpoint}:{index}", analysis_category="dynamic-api",
                    tags=["dynamic", "api", "schemathesis"],
                ))
        return findings


class FindingDeduplicator:
    """
    Groups findings by a conservative source-region identity.
    When multiple tools flag the same location, the highest-severity
    finding becomes canonical; others are marked as duplicates.
    """

    _SEVERITY_RANK = {
        "CRITICAL": 5, "HIGH": 4, "MEDIUM": 3, "LOW": 2, "INFO": 1
    }

    def deduplicate(self, findings: list[Finding]) -> list[Finding]:
        groups: dict[str, list[Finding]] = {}
        for f in findings:
            key = f.dedup_key()
            groups.setdefault(key, []).append(f)

        result: list[Finding] = []
        for group in groups.values():
            group.sort(
                key=lambda f: self._SEVERITY_RANK.get(f.severity, 0),
                reverse=True,
            )
            canonical = group[0]
            canonical.duplicate_group = canonical.id

            # Attach corroborating evidence from other tools
            for dup in group[1:]:
                if dup.source_tool != canonical.source_tool:
                    canonical.evidence.append(
                        f"{dup.source_tool}:{dup.rule_id}:{dup.start_line}"
                    )
                dup.is_duplicate = True
                dup.duplicate_group = canonical.id

            result.extend(group)

        return result


# ─────────────────────────────────────────────────────────────
# SARIF Exporter
# ─────────────────────────────────────────────────────────────

class SarifExporter:
    """Exports unified findings back to SARIF 2.1 for GitHub Security tab."""

    def export(self, findings: list[Finding], output_path: Path) -> None:
        results = []
        rules: dict[str, dict] = {}

        for f in findings:
            if f.is_duplicate:
                continue  # only export canonical findings

            rule_id = f"{f.source_tool}/{f.rule_id}"
            if rule_id not in rules:
                rules[rule_id] = {
                    "id": rule_id,
                    "name": f.rule_name,
                    "shortDescription": {"text": f.rule_name},
                    "fullDescription": {"text": f.description or f.message},
                    "defaultConfiguration": {
                        "level": self._severity_to_sarif(f.severity)
                    },
                    "properties": {
                        "tags": f.cwe + f.owasp + f.tags,
                        "security-severity": str(self._severity_to_score(f.severity)),
                    },
                }

            results.append({
                "ruleId": rule_id,
                "level": self._severity_to_sarif(f.severity),
                "message": {
                    "text": f.message,
                    "markdown": f"{f.message}\n\n**Tool:** {f.source_tool}  \n**Evidence:** {', '.join(f.evidence)}",
                },
                "locations": [
                    {
                        "physicalLocation": {
                            "artifactLocation": {"uri": f.file, "uriBaseId": "%SRCROOT%"},
                            "region": {
                                "startLine": max(f.start_line, 1),
                                "endLine": max(f.end_line or f.start_line, 1),
                                "snippet": {"text": f.code_snippet} if f.code_snippet else {},
                            },
                        }
                    }
                ],
                "properties": {
                    "category": f.category,
                    "confidence": f.confidence,
                    "evidence": f.evidence,
                    "autoFixable": f.auto_fixable,
                    "fixLevel": f.fix_level,
                },
            })

        sarif = {
            "$schema": "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json",
            "version": "2.1.0",
            "runs": [
                {
                    "tool": {
                        "driver": {
                            "name": "AgenticSOCStaticMonitoring",
                            "version": "1.0.0",
                            "informationUri": "https://github.com/combustrrr/Agentic-Kibana",
                            "rules": list(rules.values()),
                        }
                    },
                    "results": results,
                }
            ],
        }

        output_path.write_text(json.dumps(sarif, indent=2))

    @staticmethod
    def _severity_to_sarif(severity: str) -> str:
        return {
            "CRITICAL": "error",
            "HIGH": "error",
            "MEDIUM": "warning",
            "LOW": "note",
            "INFO": "none",
        }.get(severity, "warning")

    @staticmethod
    def _severity_to_score(severity: str) -> float:
        return {"CRITICAL": 9.5, "HIGH": 8.0, "MEDIUM": 5.0, "LOW": 2.0, "INFO": 0.0}.get(severity, 5.0)


# ─────────────────────────────────────────────────────────────
# CLI Entry Point
# ─────────────────────────────────────────────────────────────

@click.command()
@click.option("--input-dir", "-i", type=click.Path(exists=True), required=True,
              help="Directory containing tool output files")
@click.option("--output-dir", "-o", type=click.Path(), default="./normalized",
              help="Directory for normalized output")
@click.option("--verbose", "-v", is_flag=True)
def main(input_dir: str, output_dir: str, verbose: bool) -> None:
    """
    Normalize findings from multiple code analysis tools into a unified schema.
    """
    input_path = Path(input_dir)
    output_path = Path(output_dir)
    output_path.mkdir(parents=True, exist_ok=True)

    sarif_parser = SarifParser()
    bandit_parser = BanditParser()
    ruff_parser = RuffParser()
    vulture_parser = VultureParser()
    semgrep_parser = SemgrepParser()
    pyright_parser = PyrightParser()
    eslint_parser = EslintParser()
    tsc_parser = TscParser()
    xenon_parser = XenonParser()
    radon_parser = RadonParser()
    coverage_parser = CoverageParser()
    schemathesis_parser = SchemathesisParser()
    deduplicator = FindingDeduplicator()
    exporter = SarifExporter()

    all_findings: list[Finding] = []
    parse_errors: list[str] = []

    def retain(findings: list[Finding], artifact: Path) -> None:
        reference = artifact.relative_to(input_path).as_posix()
        for finding in findings:
            finding.raw_artifact = reference
            finding.native_result_id = finding.native_result_id or finding.id
        all_findings.extend(findings)

    def report_parse_error(artifact: Path, error: Exception) -> None:
        message = f"{artifact}: {error}"
        parse_errors.append(message)
        print(f"[ERROR] Failed to parse {message}", file=sys.stderr)

    # ── Parse SARIF files ────────────────────────────────────
    parsed_files: set[Path] = set()
    for sarif_file in input_path.rglob("*.sarif"):
        try:
            tool_hint = sarif_file.stem.split("-")[0]
            findings = sarif_parser.parse(sarif_file, tool_hint=tool_hint)
            retain(findings, sarif_file)
            parsed_files.add(sarif_file)
            if verbose:
                print(f"[SARIF] {sarif_file.name}: {len(findings)} findings")
        except Exception as e:
            report_parse_error(sarif_file, e)

    # ── Parse Bandit JSON ────────────────────────────────────
    json_files = sorted(input_path.rglob("*.json"))
    for bandit_file in (p for p in json_files if "bandit" in p.name.lower()):
        try:
            findings = bandit_parser.parse(bandit_file)
            retain(findings, bandit_file)
            parsed_files.add(bandit_file)
            if verbose:
                print(f"[Bandit] {bandit_file.name}: {len(findings)} findings")
        except Exception as e:
            report_parse_error(bandit_file, e)

    # ── Parse Ruff JSON ──────────────────────────────────────
    for ruff_file in (p for p in json_files if "ruff" in p.name.lower()):
        try:
            findings = ruff_parser.parse(ruff_file)
            retain(findings, ruff_file)
            parsed_files.add(ruff_file)
            if verbose:
                print(f"[Ruff] {ruff_file.name}: {len(findings)} findings")
        except Exception as e:
            report_parse_error(ruff_file, e)

    for semgrep_file in (p for p in json_files if "semgrep" in p.name.lower()):
        try:
            findings = semgrep_parser.parse(semgrep_file)
            retain(findings, semgrep_file)
            parsed_files.add(semgrep_file)
            if verbose:
                print(f"[Semgrep] {semgrep_file.name}: {len(findings)} findings")
        except Exception as e:
            report_parse_error(semgrep_file, e)

    for pyright_file in (p for p in json_files if "pyright" in p.name.lower()):
        try:
            findings = pyright_parser.parse(pyright_file)
            retain(findings, pyright_file)
            parsed_files.add(pyright_file)
            if verbose:
                print(f"[Pyright] {pyright_file.name}: {len(findings)} findings")
        except Exception as e:
            report_parse_error(pyright_file, e)

    for eslint_file in (p for p in json_files if "eslint" in p.name.lower()):
        try:
            findings = eslint_parser.parse(eslint_file)
            retain(findings, eslint_file)
            parsed_files.add(eslint_file)
            if verbose:
                print(f"[ESLint] {eslint_file.name}: {len(findings)} findings")
        except Exception as e:
            report_parse_error(eslint_file, e)

    # ── Parse Vulture JSON ───────────────────────────────────
    for vulture_file in (p for p in json_files if "vulture" in p.name.lower()):
        try:
            findings = vulture_parser.parse(vulture_file)
            retain(findings, vulture_file)
            parsed_files.add(vulture_file)
            if verbose:
                print(f"[Vulture] {vulture_file.name}: {len(findings)} findings")
        except Exception as e:
            report_parse_error(vulture_file, e)

    for vulture_file in (p for p in input_path.rglob("*.txt") if "vulture" in p.name.lower()):
        try:
            findings = vulture_parser.parse_text(vulture_file)
            retain(findings, vulture_file)
            parsed_files.add(vulture_file)
            if verbose:
                print(f"[Vulture] {vulture_file.name}: {len(findings)} findings")
        except Exception as e:
            report_parse_error(vulture_file, e)

    for tsc_file in (p for p in input_path.rglob("*.txt") if "tsc" in p.name.lower()):
        try:
            findings = tsc_parser.parse(tsc_file)
            retain(findings, tsc_file)
            parsed_files.add(tsc_file)
            if verbose:
                print(f"[TypeScript] {tsc_file.name}: {len(findings)} findings")
        except Exception as e:
            report_parse_error(tsc_file, e)

    for xenon_file in (p for p in input_path.rglob("*.txt") if "xenon" in p.name.lower()):
        try:
            findings = xenon_parser.parse(xenon_file)
            retain(findings, xenon_file)
            parsed_files.add(xenon_file)
            if verbose:
                print(f"[Xenon] {xenon_file.name}: {len(findings)} findings")
        except Exception as e:
            report_parse_error(xenon_file, e)

    for radon_file in (p for p in json_files if p.name.lower() == "radon-cc.json"):
        try:
            findings = radon_parser.parse(radon_file)
            retain(findings, radon_file)
            parsed_files.add(radon_file)
            if verbose:
                print(f"[Radon] {radon_file.name}: {len(findings)} findings")
        except Exception as e:
            report_parse_error(radon_file, e)

    for coverage_file in (p for p in json_files if p.name.lower() == "coverage.json"):
        try:
            findings = coverage_parser.parse(coverage_file)
            retain(findings, coverage_file)
            parsed_files.add(coverage_file)
            if verbose:
                print(f"[Coverage.py] {coverage_file.name}: {len(findings)} findings")
        except Exception as e:
            report_parse_error(coverage_file, e)

    for schemathesis_file in (p for p in input_path.rglob("*.xml")
                              if "fuzzing-results" in p.name.lower()):
        try:
            findings = schemathesis_parser.parse(schemathesis_file)
            retain(findings, schemathesis_file)
            parsed_files.add(schemathesis_file)
            if verbose:
                print(f"[Schemathesis] {schemathesis_file.name}: {len(findings)} findings")
        except Exception as e:
            report_parse_error(schemathesis_file, e)

    if parse_errors:
        raise click.ClickException(
            "normalization rejected malformed scanner artifacts:\n" + "\n".join(parse_errors)
        )

    print(f"\n Parsed input files: {len(parsed_files)}")
    print(f" Total raw findings: {len(all_findings)}")

    # ── Deduplicate ──────────────────────────────────────────
    deduplicated = deduplicator.deduplicate(all_findings)
    canonical = [f for f in deduplicated if not f.is_duplicate]
    print(f" After deduplication: {len(canonical)} unique findings "
          f"({len(all_findings) - len(canonical)} duplicates removed)")

    # ── Severity summary ─────────────────────────────────────
    for sev in ("CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"):
        count = sum(1 for f in canonical if f.severity == sev)
        if count:
            print(f"   {sev}: {count}")

    # ── Write outputs ─────────────────────────────────────────
    unified_out = output_path / "unified-findings.json"
    unified_out.write_text(json.dumps([asdict(f) for f in all_findings], indent=2))

    dedup_out = output_path / "deduplicated-findings.json"
    dedup_out.write_text(json.dumps([asdict(f) for f in canonical], indent=2))

    sarif_out = output_path / "normalized.sarif"
    exporter.export(canonical, sarif_out)

    print(f"\n Output written to: {output_dir}/")
    print(f"   unified-findings.json       ({len(all_findings)} total)")
    print(f"   deduplicated-findings.json  ({len(canonical)} unique)")
    print("   normalized.sarif            (for GitHub Security tab)")


if __name__ == "__main__":
    main()
