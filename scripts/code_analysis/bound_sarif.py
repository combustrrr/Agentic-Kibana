#!/usr/bin/env python3
"""Create a deterministic GitHub-compatible SARIF view without altering raw evidence."""
from __future__ import annotations

import argparse
import json
from pathlib import Path

LEVEL_ORDER = {"error": 0, "warning": 1, "note": 2, "none": 3}


def bound(document: dict, maximum: int) -> dict:
    remaining = maximum
    for run in document.get("runs", []):
        results = list(run.get("results") or [])
        results.sort(key=lambda row: (
            LEVEL_ORDER.get(str(row.get("level", "warning")).lower(), 4),
            str(row.get("ruleId") or ""),
            json.dumps(row.get("locations") or [], sort_keys=True),
            str(row.get("message", {}).get("text") or ""),
        ))
        run["results"] = results[:remaining]
        remaining -= len(run["results"])
    return document


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--input", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--maximum", type=int, default=5000)
    args = parser.parse_args()
    if args.maximum < 1:
        raise ValueError("maximum must be positive")
    document = json.loads(args.input.read_text(encoding="utf-8"))
    args.output.write_text(
        json.dumps(bound(document, args.maximum), separators=(",", ":")) + "\n",
        encoding="utf-8",
    )


if __name__ == "__main__":
    main()
