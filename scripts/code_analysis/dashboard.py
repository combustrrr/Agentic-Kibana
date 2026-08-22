#!/usr/bin/env python3
"""Generate a dependency-free, searchable HTML view of every normalized finding."""

from __future__ import annotations

import argparse
import json
from collections import Counter
from pathlib import Path

EXPECTED = {
    "CodeQL": ("*codeql*.sarif",), "Semgrep": ("*semgrep*.sarif", "*semgrep*.json"), "Bandit": ("*bandit*.json",),
    "Ruff": ("*ruff*.json",), "OSV-Scanner": ("*osv*.sarif",), "Gitleaks": ("*gitleaks*.sarif",),
    "Trivy": ("*trivy*.sarif",), "Checkov": ("*checkov*.sarif",), "Hadolint": ("*hadolint*.sarif",),
    "Vulture": ("*vulture*.txt", "*vulture*.json"), "Radon": ("*radon*.json",),
    "Coverage.py": ("*coverage.json",), "Pyright": ("*pyright*.json",), "ESLint": ("*eslint*.json",),
}


def coverage_manifest(artifacts: Path, findings: list[dict]) -> dict:
    counts = Counter(str(f.get("source_tool") or "Unknown") for f in findings)
    rows = []
    for tool, patterns in EXPECTED.items():
        files = sorted({str(path.relative_to(artifacts)).replace("\\", "/")
                        for pattern in patterns for path in artifacts.rglob(pattern)})
        rows.append({"tool": tool, "status": "observed" if files or counts.get(tool, 0) else "missing",
                     "artifact_files": files, "findings": counts.get(tool, 0)})
    unknown = sorted(set(counts) - set(EXPECTED))
    rows.extend({"tool": tool, "status": "observed", "artifact_files": [], "findings": counts[tool]}
                for tool in unknown)
    return {"expected_tools": len(EXPECTED), "observed_tools": sum(r["status"] == "observed" for r in rows[:len(EXPECTED)]),
            "tools": rows}


def coverage_metrics(artifacts: Path) -> dict:
    files = list(artifacts.rglob("coverage.json"))
    if not files:
        return {"status": "missing"}
    try:
        data = json.loads(files[0].read_text(encoding="utf-8"))
        totals = data.get("totals", {})
        lowest = sorted(({"file": name, "percent": info.get("summary", {}).get("percent_covered", 0)}
                         for name, info in data.get("files", {}).items()), key=lambda item: item["percent"])[:25]
        return {"status": "observed", "percent": totals.get("percent_covered"), "covered": totals.get("covered_lines"),
                "statements": totals.get("num_statements"), "lowest_files": lowest}
    except (OSError, ValueError, TypeError) as exc:
        return {"status": "invalid", "error": str(exc)}


def diagnosis(finding: dict) -> str:
    category = finding.get("category")
    evidence = finding.get("evidence") or []
    if len(evidence) > 0:
        return "Corroborated by multiple tools; review the shared code location once."
    if category == "DEPENDENCY":
        return "Review the affected package, reachable usage, and safe upgrade path."
    if category in {"SECURITY", "SECRET"}:
        return "Validate data flow and exploitability before changing security-sensitive code."
    if finding.get("auto_fixable"):
        return "Eligible for a review-only deterministic fix proposal."
    return "Review the rule context and classify as actionable or false positive."


def generate(findings: list[dict], manifest: dict, metrics: dict, output: Path) -> None:
    for finding in findings:
        finding["diagnosis"] = diagnosis(finding)
    payload = json.dumps(findings).replace("<", "\\u003c")
    meta = json.dumps({"manifest": manifest, "coverage": metrics}).replace("<", "\\u003c")
    document = """<!doctype html><html lang='en'><head><meta charset='utf-8'><meta name='viewport' content='width=device-width'>
<title>Advisory Code Analysis</title><style>
:root{color-scheme:dark;background:#0b1020;color:#e7ecf5;font:14px system-ui}body{margin:0;padding:24px}.cards{display:grid;grid-template-columns:repeat(auto-fit,minmax(150px,1fr));gap:12px}.card,section{background:#151c30;border:1px solid #2b3655;border-radius:10px;padding:14px;margin-bottom:16px}.n{font-size:26px;font-weight:700}input,select{background:#0b1020;color:#fff;border:1px solid #405071;border-radius:6px;padding:9px;margin:4px}table{width:100%;border-collapse:collapse}th,td{text-align:left;border-bottom:1px solid #293552;padding:8px;vertical-align:top}th{position:sticky;top:0;background:#151c30}.HIGH,.CRITICAL{color:#ff887d}.MEDIUM{color:#ffd166}.LOW{color:#7dd3fc}code{word-break:break-all}.scroll{max-height:68vh;overflow:auto}.muted{color:#9ba8c2}</style></head><body>
<h1>Advisory Code Analysis</h1><p class='muted'>Every normalized finding is searchable here. This dashboard is diagnostic and does not block merges.</p>
<div class='cards' id='cards'></div><section><h2>Detection coverage</h2><div id='coverage'></div></section>
<section><input id='search' size='45' placeholder='Search file, rule, concept, message…'><select id='severity'><option value=''>All severities</option></select><select id='tool'><option value=''>All tools</option></select><select id='category'><option value=''>All categories</option></select><strong id='shown'></strong></section>
<section class='scroll'><table><thead><tr><th>Severity</th><th>Location</th><th>Tool / evidence</th><th>Concept</th><th>Finding and diagnosis</th><th>Fix</th></tr></thead><tbody id='rows'></tbody></table></section>
<script id='findings' type='application/json'>""" + payload + """</script><script id='meta' type='application/json'>""" + meta + """</script><script>
const all=JSON.parse(document.querySelector('#findings').textContent),meta=JSON.parse(document.querySelector('#meta').textContent);const $=s=>document.querySelector(s), esc=s=>String(s??'').replace(/[&<>"']/g,c=>({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c]));
const count=k=>Object.entries(all.reduce((a,f)=>(a[f[k]]=(a[f[k]]||0)+1,a),{})).sort();const card=(n,t)=>`<div class=card><div class=n>${n}</div>${t}</div>`;$('#cards').innerHTML=card(all.length,'Unique findings')+card(all.reduce((n,f)=>n+(f.evidence?.length||0),0),'Duplicate evidence links')+card(all.filter(f=>f.auto_fixable).length,'Deterministic fix candidates')+card(meta.manifest.observed_tools+'/'+meta.manifest.expected_tools,'Expected tools observed');
$('#coverage').innerHTML='<table><tr><th>Tool</th><th>Status</th><th>Findings</th><th>Artifacts</th></tr>'+meta.manifest.tools.map(t=>`<tr><td>${esc(t.tool)}</td><td>${esc(t.status)}</td><td>${t.findings}</td><td>${esc(t.artifact_files.join(', '))}</td></tr>`).join('')+'</table>'+(meta.coverage.percent!=null?`<p><b>Runtime line coverage:</b> ${Number(meta.coverage.percent).toFixed(2)}%</p>`:'<p>Runtime coverage report unavailable in this aggregation.</p>');
for(const [id,key] of [['#severity','severity'],['#tool','source_tool'],['#category','category']])for(const [v] of count(key))$(id).insertAdjacentHTML('beforeend',`<option>${esc(v)}</option>`);
function render(){const q=$('#search').value.toLowerCase(),s=$('#severity').value,t=$('#tool').value,c=$('#category').value;const rows=all.filter(f=>(!s||f.severity===s)&&(!t||f.source_tool===t)&&(!c||f.category===c)&&(!q||JSON.stringify(f).toLowerCase().includes(q)));$('#shown').textContent=` ${rows.length} shown`;$('#rows').innerHTML=rows.map(f=>`<tr><td class='${esc(f.severity)}'>${esc(f.severity)}</td><td><code>${esc(f.file)}:${f.start_line}</code></td><td>${esc(f.source_tool)}<br><span class=muted>${esc((f.evidence||[]).join(', '))}</span></td><td><code>${esc(f.rule_concept)}</code></td><td>${esc(f.message)}<br><span class=muted>${esc(f.diagnosis)}</span></td><td>${f.auto_fixable?'review-only candidate':'manual'}</td></tr>`).join('')};document.querySelectorAll('input,select').forEach(e=>e.addEventListener('input',render));render();
</script></body></html>"""
    output.write_text(document, encoding="utf-8")


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--findings", type=Path, required=True)
    parser.add_argument("--artifacts", type=Path, required=True)
    parser.add_argument("--output-dir", type=Path, required=True)
    args = parser.parse_args()
    findings = json.loads(args.findings.read_text(encoding="utf-8"))
    args.output_dir.mkdir(parents=True, exist_ok=True)
    manifest, metrics = coverage_manifest(args.artifacts, findings), coverage_metrics(args.artifacts)
    (args.output_dir / "coverage-manifest.json").write_text(json.dumps({"tools": manifest, "runtime": metrics}, indent=2), encoding="utf-8")
    generate(findings, manifest, metrics, args.output_dir / "index.html")
    print(f"Dashboard contains {len(findings)} unique findings; tool coverage {manifest['observed_tools']}/{manifest['expected_tools']}.")


if __name__ == "__main__":
    main()
