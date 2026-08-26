#!/usr/bin/env python3
"""Create a validated, current full-codebase findings snapshot."""
from __future__ import annotations

import argparse
from datetime import datetime, timezone
from pathlib import Path

from monitoring import build_snapshot, canonicalize, load_json, write_json


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--raw-findings", type=Path, required=True)
    parser.add_argument("--repository", required=True)
    parser.add_argument("--commit", required=True)
    parser.add_argument("--branch", required=True)
    parser.add_argument("--workflow-run-id", action="append", required=True)
    parser.add_argument("--channel-manifest", type=Path, required=True)
    parser.add_argument("--channel-status", type=Path, required=True)
    parser.add_argument("--provenance", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    run = {
        "commit_sha": args.commit,
        "branch": args.branch,
        "workflow_run_id": args.workflow_run_id[0],
        "generated_at": datetime.now(timezone.utc).isoformat(),
    }
    current = canonicalize(load_json(args.raw_findings), args.repository, run,
                           load_json(args.channel_manifest))
    provenance = load_json(args.provenance)
    provenance["workflow_run_ids"] = args.workflow_run_id
    snapshot = build_snapshot(current, load_json(args.channel_status), provenance)
    args.output.parent.mkdir(parents=True, exist_ok=True)
    write_json(args.output, snapshot)


if __name__ == "__main__":
    main()
