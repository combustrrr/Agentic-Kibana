#!/usr/bin/env python3
"""Deterministic 10k-finding MVP scale gate."""
from __future__ import annotations
import json, tempfile, time, tracemalloc
from pathlib import Path
from dashboard import generate
from monitoring import canonicalize, compare

def main() -> None:
    manifest=json.loads(Path("config/code-analysis/required-channels.json").read_text())
    run={"commit_sha":"benchmark","branch":"benchmark","workflow_run_id":"benchmark","generated_at":"2026-08-25T00:00:00Z"}
    tools=[(x["scanner_family"],x["channel"]) for x in manifest["required_static_channels"]]
    raw=[]
    for i in range(10_000):
        tool,_=tools[i%len(tools)];raw.append({"source_tool":tool,"file":f"backend/f{i%1000}.py","start_line":i//1000+1,"rule_id":f"rule-{i%100}","rule_concept":f"concept-{i%100}","severity":["HIGH","MEDIUM","LOW"][i%3],"category":"QUALITY","code_snippet":f"operation_{i%100}({i})","message":"synthetic"})
    # Thirty percent extra evidence intentionally duplicates canonical locations.
    raw.extend({**row,"source_tool":tools[(idx+1)%len(tools)][0]} for idx,row in enumerate(raw[:3000]))
    statuses={"schema_version":"1","channels":[{"scanner_family":family,"status":"COMPLETED","channel":channel,"surface":"benchmark","artifact_files":[]} for family,channel in tools],"analysis_change_flags":[]}
    tracemalloc.start();started=time.perf_counter();base=canonicalize(raw,"benchmark/repo",run,manifest);base["baseline_id"]="benchmark";result=compare(base,base,None,statuses,{"decisions":[]})
    with tempfile.TemporaryDirectory() as directory:
        output=Path(directory)/"index.html";generate(result,statuses,output);html=output.read_text(encoding="utf-8")
        if "slice((page-1)*size,page*size)" not in html or "<option>250</option>" not in html: raise SystemExit("dashboard is not DOM-bounded")
    elapsed=time.perf_counter()-started;_,peak=tracemalloc.get_traced_memory();tracemalloc.stop()
    print(f"findings={len(base['findings'])} observations={len(base['observations'])} seconds={elapsed:.2f} peak_mib={peak/1024/1024:.2f}")
    if elapsed>30 or peak>512*1024*1024: raise SystemExit("10k scale gate failed")
if __name__=="__main__": main()
