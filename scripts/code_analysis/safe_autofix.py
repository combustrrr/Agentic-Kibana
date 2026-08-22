#!/usr/bin/env python3
"""Generate deterministic Ruff patch proposals without modifying the worktree."""

from __future__ import annotations

import argparse
import json
import subprocess
from pathlib import Path


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--findings", type=Path, required=True)
    parser.add_argument("--output-dir", type=Path, required=True)
    args = parser.parse_args()
    findings = json.loads(args.findings.read_text(encoding="utf-8"))
    candidates = [f for f in findings if f.get("source_tool") == "Ruff" and f.get("auto_fixable")]
    args.output_dir.mkdir(parents=True, exist_ok=True)
    manifest = {"mode": "review-only", "worktree_modified": False, "candidate_count": len(candidates),
                "finding_ids": [f.get("id") for f in candidates]}
    (args.output_dir / "manifest.json").write_text(json.dumps(manifest, indent=2), encoding="utf-8")
    result = subprocess.run(["python", "-m", "ruff", "check", "backend/app", "backend/tests",
                             "--config", "backend/ruff-analysis.toml", "--fix", "--diff"],
                            text=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, check=False)
    (args.output_dir / "ruff-safe-fixes.patch").write_text(result.stdout, encoding="utf-8")
    print(f"Generated review-only patch for {len(candidates)} normalized Ruff candidates; source files were not edited.")


if __name__ == "__main__":
    main()
