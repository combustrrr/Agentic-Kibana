#!/usr/bin/env python3
"""Fail closed on unsafe or non-reproducible code-analysis workflow changes."""
from __future__ import annotations

import re
from pathlib import Path
from typing import Any

import yaml

ROOT = Path(__file__).resolve().parents[2]
WORKFLOWS = ROOT / ".github" / "workflows"
ANALYSIS_WORKFLOWS = {f"0{number}-" for number in range(1, 10)}
FULL_SHA = re.compile(r"^[0-9a-f]{40}$")
USES = re.compile(r"^([^@]+)@(.+)$")
UNTRUSTED_INLINE = re.compile(r"\$\{\{\s*(?:github\.event|inputs\.)")


def _walk_steps(document: dict[str, Any]) -> list[tuple[str, dict[str, Any]]]:
    rows = []
    for job_name, job in (document.get("jobs") or {}).items():
        for step in job.get("steps") or []:
            rows.append((str(job_name), step))
    return rows


def audit() -> list[str]:
    errors: list[str] = []
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
    if auto_review.get("base_branches"):
        errors.append(".coderabbit.yaml: base_branches must not silently exclude fork PR targets")

    for relative in ("deploy/defectdojo-compose.yml", "deploy/codescene-compose.yml"):
        text = (ROOT / relative).read_text(encoding="utf-8")
        if ":latest" in text:
            errors.append(f"{relative}: mutable latest image is forbidden")
        if re.search(r'^\s+- "(?:8080|3003):', text, re.MULTILINE):
            errors.append(f"{relative}: portal port must bind to localhost")
    return errors


def main() -> None:
    errors = audit()
    if errors:
        raise SystemExit("workflow policy violations:\n- " + "\n- ".join(errors))
    print("Workflow policy passed: immutable actions, bounded jobs, safe shell inputs, read-only analysis.")


if __name__ == "__main__":
    main()
