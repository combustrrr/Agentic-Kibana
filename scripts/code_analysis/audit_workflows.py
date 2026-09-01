#!/usr/bin/env python3
"""Fail closed on unsafe or non-reproducible code-analysis workflow changes."""
from __future__ import annotations

import json
import re
from pathlib import Path
from typing import Any

import yaml

ROOT = Path(__file__).resolve().parents[2]
WORKFLOWS = ROOT / ".github" / "workflows"
ANALYSIS_WORKFLOWS = {f"0{number}-" for number in range(1, 10)}
FULL_SHA = re.compile(r"^[0-9a-f]{40}$")
USES = re.compile(r"^([^@]+)@(.+)$")
BANNED_NODE20_ACTION_SHAS = {
    "11d5960a326750d5838078e36cf38b85af677262",  # actions/checkout v4
    "a26af69be951a213d495a4c3e4e4022e16d87065",  # actions/setup-python v5
    "49933ea5288caeca8642d1e84afbd3f7d6820020",  # actions/setup-node v4
    "6d786de4d6f3531a740e445b53a42b622bbbace8",  # github/codeql-action v3
}
UNTRUSTED_INLINE = re.compile(r"\$\{\{\s*(?:github\.event|inputs\.)")
SERVICE_LAYERS = {
    "contracts",
    "ingestion_adapters",
    "domain",
    "application",
    "presentation",
    "infrastructure_adapters",
    "verification",
    "compatibility_entrypoints",
}
APPLICATION_IMPORT = re.compile(r"^\s*(?:from|import)\s+(?:backend|app|webui)(?:\.|\s|$)", re.MULTILINE)
ANALYSIS_COUPLING = re.compile(
    r"scripts[./\\]code_analysis|scripts\.code_analysis|web-of-scanners|"
    r"code-analysis-dashboard|local_service\.py",
    re.IGNORECASE,
)
RUNTIME_SOURCE_ROOTS = ("backend/app", "webui/src")
RUNTIME_BOUNDARY_FILES = (
    "backend/Dockerfile",
    "webui/Dockerfile",
    "backend/pyproject.toml",
    "backend/requirements.txt",
    "backend/requirements-dev.txt",
    "webui/package.json",
    "docker-compose.yml",
    "docker-compose.agnostic.yml",
)
RETIRED_LOCAL_SURFACES = (
    "scripts/code_analysis/local_service.py",
    "scripts/code_analysis/pull_worker.py",
    "scripts/code_analysis/publish_snapshot.py",
    "deploy/code-analysis-dashboard",
    "web-of-scanners.ps1",
)


def _walk_steps(document: dict[str, Any]) -> list[tuple[str, dict[str, Any]]]:
    rows = []
    for job_name, job in (document.get("jobs") or {}).items():
        for step in job.get("steps") or []:
            rows.append((str(job_name), step))
    return rows


def audit_service_layout() -> list[str]:
    """Validate the external-service ownership and application isolation contract."""
    errors: list[str] = []
    for retired in RETIRED_LOCAL_SURFACES:
        if (ROOT / retired).exists():
            errors.append(f"{retired}: local Issue Wall surface is retired")
    relative = "config/code-analysis/service-layout.json"
    path = ROOT / relative
    try:
        document = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        return [f"{relative}: invalid or unreadable service layout: {exc}"]
    if document.get("schema_version") != "1":
        errors.append(f"{relative}: unsupported schema_version")
    if document.get("boundary") != "read-only-external":
        errors.append(f"{relative}: service boundary must remain read-only-external")
    if document.get("forbidden_runtime_dependencies") != ["backend/app", "webui/src"]:
        errors.append(
            f"{relative}: runtime dependency boundary must name backend/app and webui/src"
        )
    layers = document.get("layers")
    if not isinstance(layers, dict):
        return [*errors, f"{relative}: layers must be an object"]
    unknown = set(layers) - SERVICE_LAYERS
    missing = SERVICE_LAYERS - set(layers)
    if unknown:
        errors.append(f"{relative}: unknown layers: {', '.join(sorted(unknown))}")
    if missing:
        errors.append(f"{relative}: missing layers: {', '.join(sorted(missing))}")
    declared: set[str] = set()
    for layer, entries in layers.items():
        if not isinstance(entries, list) or not entries:
            errors.append(f"{relative}: layer {layer} must declare at least one file")
            continue
        for entry in entries:
            if not isinstance(entry, str) or Path(entry).is_absolute() or ".." in Path(entry).parts:
                errors.append(f"{relative}: layer {layer} contains unsafe path {entry!r}")
                continue
            target = ROOT / entry
            if not target.is_file():
                errors.append(f"{relative}: layer {layer} references missing file {entry}")
                continue
            if layer != "compatibility_entrypoints":
                declared.add(entry)
            if Path(entry).parts[:2] in {("backend", "app"), ("webui", "src")}:
                errors.append(f"{relative}: analysis-owned file enters product runtime: {entry}")
    for entry in sorted(declared):
        if not entry.endswith(".py"):
            continue
        if APPLICATION_IMPORT.search((ROOT / entry).read_text(encoding="utf-8")):
            errors.append(f"{entry}: external analysis service imports application runtime code")
    return errors


def audit_runtime_isolation() -> list[str]:
    """Reject reverse dependencies from the monitored product into its observer."""
    errors: list[str] = []
    candidates: list[Path] = []
    for relative in RUNTIME_SOURCE_ROOTS:
        root = ROOT / relative
        candidates.extend(path for path in root.rglob("*") if path.is_file())
    candidates.extend(ROOT / relative for relative in RUNTIME_BOUNDARY_FILES
                      if (ROOT / relative).is_file())
    for path in sorted(set(candidates)):
        try:
            content = path.read_text(encoding="utf-8")
        except UnicodeDecodeError:
            continue
        if ANALYSIS_COUPLING.search(content):
            relative = path.relative_to(ROOT).as_posix()
            errors.append(
                f"{relative}: Agentic SOC runtime must not depend on external code analysis"
            )
    return errors


def audit() -> list[str]:
    errors = [*audit_service_layout(), *audit_runtime_isolation()]
    for path in sorted(WORKFLOWS.glob("*.y*ml")):
        relative = path.relative_to(ROOT).as_posix()
        try:
            document = yaml.load(path.read_text(encoding="utf-8"), Loader=yaml.BaseLoader)
        except yaml.YAMLError as exc:
            errors.append(f"{relative}: invalid YAML: {exc}")
            continue
        if not isinstance(document, dict) or not isinstance(document.get("jobs"), dict):
            errors.append(f"{relative}: workflow must contain a jobs mapping")
            continue
        for job_name, job in document["jobs"].items():
            if "runs-on" in job and "timeout-minutes" not in job:
                errors.append(f"{relative}: job {job_name} has no timeout-minutes")
        for job_name, step in _walk_steps(document):
            action = str(step.get("uses") or "")
            if action and not action.startswith("./"):
                match = USES.match(action)
                if not match or not FULL_SHA.fullmatch(match.group(2)):
                    errors.append(f"{relative}: job {job_name} uses mutable action {action}")
                elif (any(path.name.startswith(prefix) for prefix in ANALYSIS_WORKFLOWS)
                      and match.group(2) in BANNED_NODE20_ACTION_SHAS):
                    errors.append(
                        f"{relative}: job {job_name} uses deprecated Node 20 action {action}"
                    )
            script = str(step.get("run") or "")
            if UNTRUSTED_INLINE.search(script):
                errors.append(
                    f"{relative}: job {job_name} interpolates event/input data directly in a shell script"
                )
        if any(path.name.startswith(prefix) for prefix in ANALYSIS_WORKFLOWS):
            permissions = document.get("permissions") or {}
            for forbidden in ("contents", "issues", "pull-requests"):
                if permissions.get(forbidden) == "write":
                    errors.append(f"{relative}: analysis workflow grants {forbidden}: write globally")

    coderabbit = yaml.load(
        (ROOT / ".coderabbit.yaml").read_text(encoding="utf-8"), Loader=yaml.BaseLoader
    )
    auto_review = ((coderabbit.get("reviews") or {}).get("auto_review") or {})
    if auto_review.get("enabled") != "true":
        errors.append(".coderabbit.yaml: automatic cloud review must remain enabled")
    if auto_review.get("base_branches") != [".*"]:
        errors.append(".coderabbit.yaml: base_branches must explicitly cover every PR target")
    github_checks = ((coderabbit.get("reviews") or {}).get("tools") or {}).get(
        "github-checks"
    ) or {}
    if github_checks.get("enabled") != "true":
        errors.append(".coderabbit.yaml: GitHub Checks integration must remain enabled")
    if github_checks.get("timeout_ms") != "900000":
        errors.append(".coderabbit.yaml: GitHub Checks must wait for the scanner window")

    return errors


def main() -> None:
    errors = audit()
    if errors:
        raise SystemExit("workflow policy violations:\n- " + "\n- ".join(errors))
    print(
        "Service policy passed: architecture boundary, immutable actions, bounded jobs, "
        "safe shell inputs, and read-only analysis."
    )


if __name__ == "__main__":
    main()
