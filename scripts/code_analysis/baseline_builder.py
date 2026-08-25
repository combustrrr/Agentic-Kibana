#!/usr/bin/env python3
"""Materialize the explicitly accepted legacy run as immutable schema-v2 evidence."""
from __future__ import annotations
import argparse, json
from pathlib import Path
from monitoring import canonicalize, write_json

def main() -> None:
    p=argparse.ArgumentParser();p.add_argument("--raw-findings",type=Path,required=True);p.add_argument("--manifest",type=Path,required=True);p.add_argument("--channel-manifest",type=Path,required=True);p.add_argument("--repository",required=True);p.add_argument("--output",type=Path,required=True);a=p.parse_args()
    metadata=json.loads(a.manifest.read_text(encoding="utf-8"));raw=json.loads(a.raw_findings.read_text(encoding="utf-8"));channels=json.loads(a.channel_manifest.read_text(encoding="utf-8"))
    run={"commit_sha":metadata["baseline_commit_sha"],"branch":"claude/main","workflow_run_id":metadata["accepted_run_id"],"generated_at":metadata["accepted_at"]}
    baseline=canonicalize(raw,a.repository,run,channels);baseline["baseline_id"]=metadata["baseline_id"];baseline["accepted_run_id"]=metadata["accepted_run_id"]
    if len(baseline["findings"]) != metadata["expected_finding_count"]: raise SystemExit(f"accepted baseline count mismatch: expected {metadata['expected_finding_count']}, got {len(baseline['findings'])}")
    write_json(a.output,baseline)
if __name__=="__main__": main()
