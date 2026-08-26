#!/usr/bin/env python3
"""Run the shared normalize/validate/snapshot/dashboard/publication pipeline.

Scanner collection is intentionally separate. GitHub Actions and the QA VM feed this
command an exact-commit artifact directory and therefore share one trust boundary.
"""
from __future__ import annotations

import argparse
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path


HERE = Path(__file__).resolve().parent


def run(command: list[str]) -> None:
    subprocess.run(command, check=True)


def build(args: argparse.Namespace) -> Path:
    artifacts = args.artifacts.resolve(strict=True)
    output = args.output.resolve()
    if output.exists():
        raise ValueError(f"output already exists: {output}")
    output.parent.mkdir(parents=True, exist_ok=True)
    staging = Path(tempfile.mkdtemp(prefix=f".{output.name}-", dir=output.parent))
    normalized = staging / "normalized"
    dashboard = staging / "dashboard"
    status = staging / "channel-status.json"
    provenance = staging / "snapshot-provenance.json"
    contract = staging / "scanner-evidence-contract.json"
    snapshot = normalized / "current-snapshot.json"
    tool_catalog = getattr(
        args, "tool_catalog", Path("config/code-analysis/proposal-tool-catalog.json")
    )
    python = sys.executable
    run_ids = [item for run_id in args.workflow_run_id for item in ("--workflow-run-id", run_id)]
    try:
        run([python, str(HERE / "normalizer.py"), "--input-dir", str(artifacts),
             "--output-dir", str(normalized), "--verbose"])
        run([python, str(HERE / "evidence_contract.py"), "--manifest", str(args.manifest),
             "--artifacts", str(artifacts), "--repository", args.repository,
             "--commit", args.commit, *run_ids, "--output", str(contract)])
        run([python, str(HERE / "channel_status.py"), "--manifest", str(args.manifest),
             "--artifacts", str(artifacts), "--findings", str(normalized / "unified-findings.json"),
             "--evidence-contract", str(contract), "--repository", args.repository,
             "--commit", args.commit,
             "--output", str(status)])
        run([python, str(HERE / "provenance.py"), "--artifacts", str(artifacts),
             "--commit", args.commit, *run_ids, "--output", str(provenance)])
        run([python, str(HERE / "snapshot.py"), "--raw-findings", str(normalized / "unified-findings.json"),
             "--repository", args.repository, "--commit", args.commit, "--branch", args.branch,
             *run_ids, "--channel-manifest", str(args.manifest), "--channel-status", str(status),
             "--provenance", str(provenance), "--tool-catalog", str(tool_catalog),
             "--artifacts", str(artifacts), "--output", str(snapshot)])
        run([python, str(HERE / "dashboard.py"), "--snapshot", str(snapshot),
             "--output-dir", str(dashboard)])
        staging.rename(output)
    except BaseException:
        shutil.rmtree(staging, ignore_errors=True)
        raise
    if args.publication_root:
        run([python, str(HERE / "publish_snapshot.py"), "--source", str(output / "dashboard"),
             "--publication-root", str(args.publication_root)])
    return output


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--artifacts", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--repository", required=True)
    parser.add_argument("--commit", required=True)
    parser.add_argument("--branch", required=True)
    parser.add_argument("--workflow-run-id", action="append", required=True)
    parser.add_argument("--manifest", type=Path,
                        default=Path("config/code-analysis/required-channels.json"))
    parser.add_argument("--tool-catalog", type=Path,
                        default=Path("config/code-analysis/proposal-tool-catalog.json"))
    parser.add_argument("--publication-root", type=Path)
    args = parser.parse_args()
    built = build(args)
    print(f"publishable pipeline output: {built}")


if __name__ == "__main__":
    main()
