#!/usr/bin/env python3
"""Generate the bounded, read-only current findings dashboard."""
from __future__ import annotations

import argparse
import json
from collections import Counter
from pathlib import Path


def load(path: Path) -> dict:
    return json.loads(path.read_text(encoding="utf-8"))


def validate_snapshot(snapshot: dict) -> None:
    if snapshot.get("schema_version") != "snapshot-v1" or snapshot.get("publishable") is not True:
        raise ValueError("dashboard requires a publishable snapshot-v1 document")
    findings = snapshot.get("canonical_findings", [])
    advisories = snapshot.get("ai_advisories", [])
    observations = snapshot.get("observations", [])
    if snapshot.get("finding_count") != len(findings) + len(advisories):
        raise ValueError("snapshot finding count does not reconcile")
    if snapshot.get("observation_count") != len(observations):
        raise ValueError("snapshot observation count does not reconcile")


def github_summary(snapshot: dict) -> str:
    validate_snapshot(snapshot)
    severities = Counter(row.get("severity", "UNKNOWN") for row in snapshot["canonical_findings"])
    channels = snapshot["channel_status"]
    additional = snapshot.get("additional_channels", [])
    observed_additional = [
        row for row in additional
        if row.get("status") in {"CONFIGURED_COMPLETE", "COMPLETED_OPTIONAL"}
    ]
    lines = ["## Issue Wall — Web of Scanners", "",
             f"- **Snapshot commit:** `{snapshot['commit_sha']}`",
             f"- **Required channels complete:** {sum(c['status'] == 'COMPLETED' for c in channels)}/{len(channels)}",
             f"- **Canonical findings:** {snapshot['finding_count']:,}",
             f"- **Raw observations:** {snapshot['observation_count']:,}",
             f"- **AI advisories:** {snapshot['ai_advisory_count']:,}",
             f"- **Additional lanes observed:** {len(observed_additional)}/{len(additional)} (not part of required coverage)",
             "- **Mode:** read-only; no Issues, patches, comments, history, or remediation",
             "- **Offline launch:** download and extract the artifact, then open `dashboard/index.html`", "",
             "| Severity | Findings |", "|---|---:|",
             *[f"| {key} | {value:,} |" for key, value in sorted(severities.items())]]
    return "\n".join(lines) + "\n"


def artifact_readme(snapshot: dict) -> str:
    """Return the offline-first launch guide shipped beside Issue Wall."""
    validate_snapshot(snapshot)
    return "\n".join([
        "# Start here — Issue Wall",
        "",
        "This is the read-only developer portal for the Web of Scanners.",
        "",
        "1. Extract the complete GitHub Actions artifact.",
        "2. Open `dashboard/index.html` in a modern browser.",
        "3. Start with the risk report, top affected files, and Where to start guidance.",
        "4. Use the Fix queue, filters, CSV export, and evidence drawer to investigate.",
        "5. Use the Web of Scanners controls to open GitHub's authenticated Actions pages.",
        "",
        f"- Repository: `{snapshot['repository_identity']}`",
        f"- Branch: `{snapshot['branch']}`",
        f"- Exact commit: `{snapshot['commit_sha']}`",
        f"- Canonical findings: {snapshot['finding_count']:,}",
        f"- Raw observations: {snapshot['observation_count']:,}",
        "",
        "Keep the files together. Issue Wall is self-contained and does not require a local server.",
        "The JSON downloads are evidence records, not instructions to execute scanner output.",
        "",
    ])


def _generate_legacy(snapshot: dict, output: Path) -> None:
    validate_snapshot(snapshot)
    payload = json.dumps(snapshot, separators=(",", ":"), ensure_ascii=False).replace("<", "\\u003c")
    template = r'''<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width"><title>Code Quality &amp; Security Findings</title><style>
:root{color-scheme:dark;background:#07111f;color:#e7eef9;font:14px Inter,system-ui,sans-serif}*{box-sizing:border-box}body{margin:0;padding:24px;max-width:1800px;margin-inline:auto}h1{margin-bottom:5px}.muted{color:#9eb0ca}.bar{display:flex;gap:12px;align-items:center;flex-wrap:wrap}.cards{display:grid;grid-template-columns:repeat(auto-fit,minmax(155px,1fr));gap:12px;margin:20px 0}.card,section,dialog{background:#111d30;border:1px solid #2a405f;border-radius:10px;padding:15px}.value{font-size:25px;font-weight:760}.ok{color:#75d5a6}.bad,.CRITICAL,.HIGH{color:#ff928a}.MEDIUM{color:#ffd166}.LOW,.INFO{color:#8fc7ff}input,select,button{background:#07111f;color:#fff;border:1px solid #49678e;border-radius:6px;padding:9px}button{cursor:pointer}button:disabled{opacity:.45}.filters{display:flex;gap:8px;flex-wrap:wrap;margin:14px 0}.filters input{min-width:320px;flex:1}.scroll{max-height:64vh;overflow:auto;padding:0}table{width:100%;border-collapse:collapse}th,td{text-align:left;border-bottom:1px solid #253b58;padding:9px;vertical-align:top}th{position:sticky;top:0;background:#111d30;z-index:1}.pill{display:inline-block;padding:2px 7px;border:1px solid #49678e;border-radius:12px;margin:2px}.pager{display:flex;justify-content:flex-end;align-items:center;gap:8px;margin:10px 0}code{word-break:break-all}dialog{color:inherit;width:min(1000px,92vw);max-height:88vh;overflow:auto}dialog::backdrop{background:#020713cc}.evidence{padding:10px;margin:8px 0;background:#081425;border-left:3px solid #557ba9}.charts{display:grid;grid-template-columns:repeat(auto-fit,minmax(260px,1fr));gap:12px}.chart-row{display:grid;grid-template-columns:minmax(90px,1fr) 3fr 45px;gap:7px;margin:5px 0}.track{background:#07111f;border-radius:4px}.fill{height:100%;min-height:8px;background:#4d92da;border-radius:4px}
</style></head><body><h1>Code Quality &amp; Security — Current Snapshot</h1><div class="bar muted"><span>Commit <code id="commit"></code></span><span id="generated"></span><span id="complete"></span><span class="ok">PUBLISHABLE</span></div><div class="cards" id="cards"></div><div class="charts" id="charts"></div><section><div class="bar"><h2>All canonical findings</h2><label><input type="checkbox" id="ai"> AI advisories</label></div><div class="filters"><input id="search" placeholder="Search concept, message, file, scanner, rule…"><select id="severity"><option value="">All severities</option></select><select id="category"><option value="">All categories</option></select><select id="component"><option value="">All components</option></select><select id="scanner"><option value="">All scanners</option></select></div><div class="pager"><strong id="shown"></strong><select id="pageSize"><option>50</option><option selected>100</option><option>250</option></select><button id="previous">Previous</button><span id="page"></span><button id="next">Next</button></div><div class="scroll"><table><thead><tr><th>Severity</th><th>Concept</th><th>Location</th><th>Category</th><th>Evidence</th><th></th></tr></thead><tbody id="rows"></tbody></table></div></section><section><h2>Required scanner channels</h2><div class="scroll"><table><thead><tr><th>Surface</th><th>Channel</th><th>Family</th><th>Status</th><th>Findings</th></tr></thead><tbody id="channels"></tbody></table></div></section><p><a href="raw-observations.json" download>Download raw observations</a> · <a href="current-snapshot.json" download>Download current snapshot</a></p><dialog id="detail"><button id="close">Close</button><div id="detailBody"></div></dialog><script id="snapshot" type="application/json">__PAYLOAD__</script><script>
const data=JSON.parse(document.querySelector('#snapshot').textContent),$=s=>document.querySelector(s),esc=s=>String(s??'').replace(/[&<>"']/g,c=>({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c]));const obs=new Map(data.observations.map(x=>[x.observation_id,x]));let page=1;$('#commit').textContent=data.commit_sha;$('#generated').textContent='Generated '+data.generated_at;$('#complete').textContent=`${data.channel_status.filter(x=>x.status==='COMPLETED').length}/${data.channel_status.length} channels complete`;const card=(v,t)=>`<div class=card><div class=value>${v}</div><div class=muted>${t}</div></div>`;$('#cards').innerHTML=card(data.finding_count.toLocaleString(),'Canonical findings')+card(data.observation_count.toLocaleString(),'Raw observations')+card(data.deterministic_finding_count.toLocaleString(),'Deterministic')+card(data.ai_advisory_count.toLocaleString(),'AI advisory');const base=data.canonical_findings,all=[...base,...data.ai_advisories];const values=key=>[...new Set(all.map(x=>x[key]).filter(Boolean))].sort();for(const [id,key] of [['#severity','severity'],['#category','category'],['#component','component']])for(const value of values(key))$(id).insertAdjacentHTML('beforeend',`<option>${esc(value)}</option>`);for(const value of [...new Set(all.flatMap(x=>x.supporting_scanner_families||[]))].sort())$('#scanner').insertAdjacentHTML('beforeend',`<option>${esc(value)}</option>`);function chart(title,key){const counts={};for(const row of base)counts[row[key]||'Unknown']=(counts[row[key]||'Unknown']||0)+1;const entries=Object.entries(counts).sort((a,b)=>b[1]-a[1]).slice(0,12),max=Math.max(...entries.map(x=>x[1]),1);return `<section><h3>${title}</h3>${entries.map(([k,v])=>`<div class=chart-row><span>${esc(k)}</span><span class=track><span class=fill style="display:block;width:${v/max*100}%"></span></span><b>${v}</b></div>`).join('')}</section>`}$('#charts').innerHTML=chart('Severity','severity')+chart('Category','category')+chart('Component','component');$('#channels').innerHTML=data.channel_status.map(c=>`<tr><td>${esc(c.surface)}</td><td>${esc(c.channel)}</td><td>${esc(c.scanner_family)}</td><td class=${c.status==='COMPLETED'?'ok':'bad'}>${esc(c.status)}</td><td>${Number(c.finding_count||0).toLocaleString()}</td></tr>`).join('');function details(id){const f=all.find(x=>x.stable_id===id),e=(f.observation_ids||[]).map(x=>obs.get(x)).filter(Boolean);$('#detailBody').innerHTML=`<h2>${esc(f.concept)} · <span class=${esc(f.severity)}>${esc(f.severity)}</span></h2><p><code>${esc(f.file)}:${f.start_line}</code></p><p>${esc(f.message)}</p><p>${f.scanner_family_count} independent scanner families · ${f.observation_count} observations</p><h3>Supporting evidence</h3>${e.map(x=>`<div class=evidence><b>${esc(x.scanner_family)}</b> · ${esc(x.channel)} · <code>${esc(x.rule)}</code><p>${esc(x.message)}</p><code>${esc(x.file)}:${x.start_line}</code><br><span class=muted>Native result: ${esc(x.native_result_id)} · Analysis: ${esc(x.analysis_category)} · Version: ${esc(x.tool_version)} · Artifact: ${esc(x.raw_artifact)}</span></div>`).join('')}`;$('#detail').showModal()}window.details=details;function render(reset=false){if(reset)page=1;const source=$('#ai').checked?data.ai_advisories:base,q=$('#search').value.toLowerCase(),sev=$('#severity').value,cat=$('#category').value,comp=$('#component').value,scanner=$('#scanner').value,size=Number($('#pageSize').value),filtered=source.filter(f=>(!sev||f.severity===sev)&&(!cat||f.category===cat)&&(!comp||f.component===comp)&&(!scanner||(f.supporting_scanner_families||[]).includes(scanner))&&(!q||JSON.stringify(f).toLowerCase().includes(q))),pages=Math.max(1,Math.ceil(filtered.length/size));page=Math.min(page,pages);const shown=filtered.slice((page-1)*size,page*size);$('#shown').textContent=`${filtered.length.toLocaleString()} matching`;$('#page').textContent=`Page ${page} of ${pages}`;$('#previous').disabled=page===1;$('#next').disabled=page===pages;$('#rows').innerHTML=shown.map(f=>`<tr><td class=${esc(f.severity)}>${esc(f.severity)}</td><td><b>${esc(f.concept)}</b><br><span class=muted>${esc(f.message)}</span></td><td><code>${esc(f.file)}:${f.start_line}</code></td><td>${esc(f.category)}</td><td><b>${f.scanner_family_count}</b> families / ${f.observation_count} observations<br>${(f.supporting_scanner_families||[]).map(x=>`<span class=pill>${esc(x)}</span>`).join('')}</td><td><button onclick="details('${esc(f.stable_id)}')">Evidence</button></td></tr>`).join('')}document.querySelectorAll('input,select').forEach(x=>x.addEventListener('input',()=>render(true)));$('#previous').onclick=()=>{page--;render()};$('#next').onclick=()=>{page++;render()};$('#close').onclick=()=>$('#detail').close();render();
</script></body></html>'''
    output.write_text(template.replace("__PAYLOAD__", payload), encoding="utf-8")


def generate(snapshot: dict, output: Path) -> None:
    """Render the current UI from the separately reviewable static template."""
    validate_snapshot(snapshot)
    payload = json.dumps(snapshot, separators=(",", ":"), ensure_ascii=False).replace("<", "\\u003c")
    template = Path(__file__).with_name("dashboard_template.html").read_text(encoding="utf-8")
    output.write_text(template.replace("__PAYLOAD__", payload), encoding="utf-8")


def write_dashboard(snapshot: dict, output_dir: Path) -> None:
    output_dir.mkdir(parents=True, exist_ok=True)
    generate(snapshot, output_dir / "index.html")
    (output_dir / "current-snapshot.json").write_text(json.dumps(snapshot, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
    (output_dir / "raw-observations.json").write_text(json.dumps(snapshot["observations"], indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
    (output_dir / "github-summary.md").write_text(github_summary(snapshot), encoding="utf-8")
    (output_dir / "START_HERE.md").write_text(artifact_readme(snapshot), encoding="utf-8")


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--snapshot", type=Path, required=True)
    parser.add_argument("--output-dir", type=Path, required=True)
    args = parser.parse_args()
    write_dashboard(load(args.snapshot), args.output_dir)


if __name__ == "__main__":
    main()
