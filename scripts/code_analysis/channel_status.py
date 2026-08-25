#!/usr/bin/env python3
"""Validate configured scanner channels against retained artifacts."""
from __future__ import annotations
import argparse, json
from collections import Counter
from pathlib import Path

def build(manifest: dict, artifacts: Path, findings: list[dict] | None = None) -> dict:
    counts=Counter(str(row.get("source_tool") or "Unknown") for row in (findings or []))
    channels=[]
    for configured in manifest["required_static_channels"]:
        files=sorted({str(path.relative_to(artifacts)).replace("\\","/") for pattern in configured["artifact_patterns"] for path in artifacts.rglob(pattern)})
        observed=bool(files or counts.get(str(configured["scanner_family"]),0))
        channels.append({**configured,"status":"COMPLETED" if observed else "NOT_CONFIGURED","artifact_files":files,"finding_count":counts.get(str(configured["scanner_family"]),0)})
    return {"schema_version":"1","channels":channels,"analysis_change_flags":[]}
def main() -> None:
    p=argparse.ArgumentParser();p.add_argument("--manifest",type=Path,required=True);p.add_argument("--artifacts",type=Path,required=True);p.add_argument("--findings",type=Path);p.add_argument("--output",type=Path,required=True);a=p.parse_args()
    findings=json.loads(a.findings.read_text(encoding="utf-8")) if a.findings else []
    result=build(json.loads(a.manifest.read_text(encoding="utf-8")),a.artifacts,findings);a.output.write_text(json.dumps(result,indent=2,sort_keys=True)+"\n",encoding="utf-8")
    missing=[x["channel"] for x in result["channels"] if x["status"]!="COMPLETED"]
    if missing: raise SystemExit("required scanner channels missing: "+", ".join(missing))
if __name__=="__main__": main()
