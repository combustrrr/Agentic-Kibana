"""GitHub-only discovery, exact-run collection, and current report publication.

Uses the job's scoped GH_TOKEN. Source code is never executed by this controller.
"""
from __future__ import annotations

import argparse
import gzip
import io
import json
import os
import shutil
import subprocess
import tempfile
import uuid
import zipfile
from pathlib import Path
from urllib.parse import quote

from scripts.code_analysis.hosted import accept, analysis_key, digest, load, now, reconcile, target, write


class SupersededReport(ValueError):
    """A newer upstream identity appeared while a producer report downloaded."""


def gh(*args: str, payload: object | None = None, binary: bool = False):
    command = ['gh', *args]
    if payload is not None:
        command += ['--input', '-']
    result = subprocess.run(command, input=json.dumps(payload).encode() if payload is not None else None,
                            stdout=subprocess.PIPE, stderr=subprocess.PIPE, check=False)
    if result.returncode:
        # Never echo authenticated commands, environment, or arbitrary response bodies.
        raise RuntimeError(f"GitHub request failed ({result.returncode}): {' '.join(args[:2])}")
    if binary:
        return result.stdout
    return json.loads(result.stdout) if result.stdout.strip() else None


def api(path: str, payload: object | None = None, method: str | None = None):
    args = ['api', path, '-H', 'X-GitHub-Api-Version: 2022-11-28']
    if method:
        args += ['--method', method]
    return gh(*args, payload=payload)


def pages(path: str, field: str | None = None) -> list:
    all_rows = []
    for page in range(1, 1001):
        result = api(f"{path}{'&' if '?' in path else '?'}per_page=100&page={page}")
        rows = result[field] if field else result
        if not isinstance(rows, list):
            raise ValueError('incomplete GitHub listing')
        all_rows.extend(rows)
        if len(rows) < 100:
            return all_rows
    raise ValueError('GitHub listing exceeds bounded pagination; retain previous inventory')


def discover(config: dict) -> list[dict]:
    repo = config['source_repository']
    branches = pages(f'repos/{repo}/branches')
    prs = pages(f'repos/{repo}/pulls?state=open')
    result = [target(repo, b['name'], b['commit']['sha']) for b in branches]
    for p in prs:
        if p['head'].get('repo') is None:
            raise ValueError(f"PR {p['number']} source repository unavailable; retain previous inventory")
        result.append(target(repo, p['head']['ref'], p['head']['sha'], pr=p['number'],
                             source_repository=p['head']['repo']['full_name'],
                             base_sha=p['base']['sha'], base_branch=p['base']['ref']))
    return sorted(result, key=lambda r: (0 if r['kind'] == 'branch' and r['branch'] == config['preferred_branch']
                                         else 1 if r['pr'] else 2, r['label']))


def release(repository: str, tag: str, *, create: bool = False) -> dict | None:
    # Listing distinguishes an absent release from an authentication/network error.
    found = next((r for r in pages(f'repos/{repository}/releases') if r['tag_name'] == tag), None)
    if found is None and create:
        found = api(f'repos/{repository}/releases', {'tag_name': tag, 'name': tag,
                    'body': '{}', 'make_latest': 'false'})
    return found


def save_state(repository: str, rel: dict, state: dict) -> None:
    body = json.dumps(state, separators=(',', ':'))
    if len(body.encode()) > 120_000:
        raise ValueError('current target manifest exceeds release-body capacity')
    api(f"repos/{repository}/releases/{rel['id']}", {'body': body}, 'PATCH')


def request_refresh(state: dict, selected: str) -> None:
    matches = [row for row in state['targets'] if row['id'] == selected or row['label'] == selected
               or (row['kind'] == 'pr' and f"PR #{row['pr']}" == selected)]
    if len(matches) != 1:
        raise ValueError('Manual refresh requires one active target ID, branch name, or PR #number')
    row = matches[0]
    row.update(status='queued', manual_refresh=True)
    for field in ('request_id', 'scan_run_id'):
        row.pop(field, None)


def scan(config: dict, refresh_target: str | None = None) -> None:
    host = config['analysis_repository']
    rel = release(host, 'current-analysis-state', create=True)
    state = json.loads(rel['body'] or '{}')
    # No mutation until full discovery succeeds.
    state = reconcile(state, discover(config), now())
    if refresh_target:
        request_refresh(state, refresh_target)
    # Explicit operator retries precede automatic backfill without removing any
    # active targets. The request persists if both analysis slots are occupied.
    state['targets'].sort(key=lambda row: not row.get('manual_refresh', False))
    info = api(f'repos/{host}')
    branch = info['default_branch']
    tooling = api(f"repos/{host}/commits/{quote(branch, safe='')}")['sha']
    runs = pages(f'repos/{host}/actions/workflows/11-source-analysis.yml/runs', 'workflow_runs')
    by_title = {r['display_title']: r for r in reversed(runs)}
    by_id = {r['id']: r for r in runs}
    running = sum(r['status'] != 'completed' for r in runs)
    publication = release(config['publishing_repository'], 'current-reports')
    retained = {r.get('collected_run') for r in json.loads(publication['body'] or '{}').get('targets', [])} if publication else set()
    artifact_cache, expired_runs = {}, set()
    for row in state['targets']:
        key = analysis_key(row, tooling, config)
        if row.get('analysis_key') != key:
            row.update(analysis_key=key, status='queued')
            row.pop('request_id', None)
            row.pop('scan_run_id', None)
        if row.get('request_id'):
            run = by_id.get(row.get('scan_run_id')) or by_title.get('Source analysis ' + row['request_id'])
            if run:
                row['scan_run_id'] = run['id']
                row['run_attempt'] = run['run_attempt']
                row['status'] = 'scanning' if run['status'] != 'completed' else 'collected'
                row['run_conclusion'] = run['conclusion']
            # A durable published report survives artifact expiry. If handoff
            # expired before publication, make the target discoverable for retry.
            if run and run['status'] == 'completed' and f"{run['id']}-{run['run_attempt']}" not in retained:
                if run['id'] not in artifact_cache:
                    artifact_cache[run['id']] = pages(f"repos/{host}/actions/runs/{run['id']}/artifacts", 'artifacts')
                expired = any(a['name'] == f"hosted-report-{run['id']}-{run['run_attempt']}" and a['expired']
                              for a in artifact_cache[run['id']])
                if expired:
                    expired_runs.add(run['id'])
                    row.pop('request_id', None)
                    row.pop('scan_run_id', None)
                    row.update(status='queued', retry_reason='Report handoff expired before durable publication')
                else:
                    continue
            else:
                # Never repeat a dispatch whose outcome is uncertain.
                continue
        # Reuse only a completed source-only analysis with identical identity/config.
        reusable = None if row.get('manual_refresh') else next((x for x in state['targets'] if x['id'] != row['id']
                         and x.get('analysis_key') == key and x.get('status') == 'collected'
                         and x.get('scan_run_id') not in expired_runs), None)
        if reusable:
            row.update(scan_run_id=reusable['scan_run_id'], run_attempt=reusable['run_attempt'],
                       tooling_sha=reusable['tooling_sha'], status='collected')
            continue
        if running >= config['max_parallel_analyses']:
            continue
        request_id = uuid.uuid4().hex
        row.update(request_id=request_id, status='dispatching', tooling_sha=tooling)
        row.pop('manual_refresh', None)
        save_state(host, rel, state)  # Intent persists before side effects.
        dispatched = api(f'repos/{host}/actions/workflows/11-source-analysis.yml/dispatches',
            {'ref': branch, 'return_run_details': True, 'inputs': {'target': json.dumps(row), 'tooling_sha': tooling,
                                      'request_id': request_id}})
        if dispatched and dispatched.get('workflow_run_id'):
            row.update(scan_run_id=dispatched['workflow_run_id'], run_attempt=1)
        row['status'] = 'scanning'
        running += 1
    state.update(preferred_branch=config['preferred_branch'], analysis_repository=host)
    save_state(host, rel, state)
    print(json.dumps({'targets': len(state['targets']), 'running': running,
                      'queued': sum(r['status'] == 'queued' for r in state['targets'])}))


def extract_zip(data: bytes, destination: Path) -> None:
    with zipfile.ZipFile(io.BytesIO(data)) as archive:
        total = 0
        for member in archive.infolist():
            path = destination / member.filename
            total += member.file_size
            if total > 900_000_000 or not path.resolve().is_relative_to(destination.resolve()) or '\\' in member.filename:
                raise ValueError('unsafe or oversized report archive')
            if (member.external_attr >> 16) & 0o170000 == 0o120000:
                raise ValueError('symlink in report archive')
        archive.extractall(destination)


def validate_bundle(destination: Path, report: dict) -> None:
    findings = load(destination / 'findings.json')
    if not isinstance(findings, list) or len(findings) != report.get('finding_count'):
        raise ValueError('hosted finding count does not reconcile')
    identifiers = [f['id'] for f in findings]
    if len(set(identifiers)) != len(identifiers):
        raise ValueError('duplicate hosted finding identity')
    details = [row for path in (destination / 'details').glob('*.json') for row in load(path)]
    if len(details) != len(findings) or {r['id'] for r in details} != set(identifiers):
        raise ValueError('hosted detail pages do not reconcile')
    origins = {o['observation_id'] for row in details for o in row['origins']}
    channel_origins = [oid for c in report['channels'] for oid in c['observation_ids']]
    if (len(channel_origins) != report['observation_count'] or len(set(channel_origins)) != len(channel_origins)
            or set(channel_origins) != origins):
        raise ValueError('hosted observation provenance does not reconcile')


def collect(config: dict, row: dict, destination: Path) -> dict:
    host, run_id = config['analysis_repository'], row['scan_run_id']
    run = api(f'repos/{host}/actions/runs/{run_id}')
    if run['path'] != '.github/workflows/11-source-analysis.yml' or run['head_sha'] != row['tooling_sha'] or run['status'] != 'completed':
        raise ValueError('producer workflow identity mismatch')
    artifacts = pages(f'repos/{host}/actions/runs/{run_id}/artifacts', 'artifacts')
    candidates = [a for a in artifacts if a['name'] == f"hosted-report-{run_id}-{row['run_attempt']}" and not a['expired']]
    if len(candidates) != 1:
        raise ValueError('exact producer report missing or expired')
    archive = gh('api', f"repos/{host}/actions/artifacts/{candidates[0]['id']}/zip", binary=True)
    extract_zip(archive, destination)
    report = load(destination / 'report.json')
    if report.get('source_boundary') != 'isolated-tooling-v1':
        raise ValueError('producer predates the isolated source/tooling boundary; rescan required')
    if any('.analysis-tooling' in str(f.get('file', '')).replace('\\', '/').split('/')
           for f in load(destination / 'findings.json')):
        raise ValueError('mixed source evidence: scanner traversed the trusted tooling checkout')
    validate_bundle(destination, report)
    if (report.get('schema_version') == 'hosted-report-v1' and report.get('target', {}).get('kind') == 'branch'
            and row['kind'] == 'branch' and report.get('tooling_sha') == row['tooling_sha']
            and analysis_key(report['target'], row['tooling_sha'], config) == row['analysis_key']):
        report['target'] = {k: row.get(k) for k in ('id', 'repository', 'source_repository', 'kind', 'branch',
                                                 'pr', 'head_sha', 'base_sha', 'base_branch', 'label')}
        # Keep the producer envelope on disk immutable so aliases share the same
        # content-addressed asset. Only this validation view uses the target alias.
    if report.get('schema_version') != 'hosted-report-v1' or not accept(row, report):
        raise ValueError('report target/revision mismatch')
    if report.get('tooling_sha') != row['tooling_sha'] or report.get('producer_run_attempt') != row['run_attempt']:
        raise ValueError('report producer attempt mismatch')
    if {str(r['id']) for r in report['producer_runs']} != {str(run_id)}:
        raise ValueError('mixed producer runs')
    return report


def publish(config: dict, output: Path) -> None:
    host, repo = config['analysis_repository'], config['publishing_repository']
    upstream = release(host, 'current-analysis-state')
    if not upstream:
        raise ValueError('analysis discovery state has not been initialized')
    scan_state = json.loads(upstream['body'])
    rel = release(repo, 'current-reports', create=True)
    previous = json.loads(rel['body'] or '{}')
    state = reconcile(previous, discover(config), now())
    state.update(preferred_branch=config['preferred_branch'], analysis_repository=host)
    runs = {r['id']: r for r in scan_state['targets']}
    # Workflow completion notifications may be suppressed or delayed. Resolve the
    # unique persisted dispatch nonce, then collect that exact run and attempt.
    producers = pages(f'repos/{host}/actions/workflows/11-source-analysis.yml/runs', 'workflow_runs')
    by_title = {r['display_title']: r for r in reversed(producers)}
    by_id = {r['id']: r for r in producers}
    for row in runs.values():
        producer = by_id.get(row.get('scan_run_id')) or by_title.get('Source analysis ' + row.get('request_id', ''))
        if producer and producer['head_sha'] == row.get('tooling_sha'):
            row.update(scan_run_id=producer['id'], run_attempt=producer['run_attempt'],
                       status='collected' if producer['status'] == 'completed' else 'scanning')
    existing = {a['name']: a for a in pages(f"repos/{repo}/releases/{rel['id']}/assets")}
    uploaded = set(existing)
    with tempfile.TemporaryDirectory(prefix='dashboard-publish-') as temporary:
        work = Path(temporary)
        for row in state['targets']:
            scan_row = runs.get(row['id'], {})
            same = scan_row.get('head_sha') == row['head_sha'] and scan_row.get('base_sha') == row.get('base_sha')
            if same:
                for field in ('scan_run_id', 'run_attempt', 'tooling_sha'):
                    if field in scan_row:
                        row[field] = scan_row[field]
            if same and scan_row.get('scan_run_id') and scan_row.get('status') == 'collected':
                key = str(scan_row['scan_run_id']) + '-' + str(scan_row['run_attempt'])
                if row.get('collected_run') != key:
                    try:
                        report_dir = work / row['id']
                        report = collect(config, scan_row, report_dir)
                        # Recheck before making results visible; collection may take minutes.
                        latest = next((r for r in discover(config) if r['id'] == row['id']), None)
                        if latest is None or not accept(latest, report):
                            # Preserve/materialize the previous report below. Aborting
                            # this loop would leave its manifest URL missing on Pages.
                            if latest is not None:
                                row.update(latest, checked_at=now())
                            raise SupersededReport('target changed during collection; previous report retained')
                        content = {p.relative_to(report_dir).as_posix(): load(p) for p in report_dir.rglob('*.json')}
                        packed = gzip.compress(json.dumps(content, separators=(',', ':')).encode(), mtime=0)
                        name = 'report-' + digest(content) + '.json.gz'
                        bundle = work / name
                        bundle.write_bytes(packed)
                        if name not in uploaded:
                            gh('release', 'upload', 'current-reports', str(bundle), '--repo', repo, binary=True)
                            uploaded.add(name)
                        row.update(report='reports/' + name[7:-8], asset=name, collected_run=key,
                                   analyzed_sha=report['analyzed_sha'], status=report['status'])
                        row.pop('error', None)
                    except SupersededReport as exc:
                        row.update(status='stale', error=str(exc))
                    except (ValueError, RuntimeError) as exc:
                        row.update(status='failed', error=str(exc))
            elif same:
                row['status'] = scan_row.get('status', 'queued')
                if row['status'] == 'dispatching':
                    row['status'] = 'queued'
            if row.get('asset'):
                name = row['asset']
                bundle = work / name
                if not bundle.exists():
                    asset = existing.get(name)
                    if not asset:
                        raise ValueError('manifest references a missing retained report')
                    bundle.write_bytes(gh('api', f"repos/{repo}/releases/assets/{asset['id']}", '-H', 'Accept: application/octet-stream', binary=True))
                unpacked = gzip.decompress(bundle.read_bytes())
                if len(unpacked) > config['site_limit_bytes']:
                    raise ValueError('retained report exceeds site limit')
                documents = json.loads(unpacked)
                if documents.get('report.json', {}).get('source_boundary') != 'isolated-tooling-v1':
                    row.update(status='failed', error='Retained report predates the isolated source/tooling boundary; rescan required')
                    for field in ('report', 'asset', 'collected_run'):
                        row.pop(field, None)
                    continue
                for name, value in documents.items():
                    path = output / 'data' / row['report'] / name
                    if not path.resolve().is_relative_to(output.resolve()):
                        raise ValueError('unsafe retained report path')
                    write(path, value)
        write(output / 'data' / 'index.json', state)
        # Keep one small shell and fetch compressed data on demand. Pages serves the
        # bytes; the browser decompresses explicitly, without a server-side API.
        for path in (output / 'data').rglob('*.json'):
            path.with_suffix('.json.gz').write_bytes(gzip.compress(path.read_bytes(), mtime=0))
            path.unlink()
        size = sum(p.stat().st_size for p in output.rglob('*') if p.is_file())
        state['metrics'] = {'site_bytes': size, 'site_limit_bytes': config['site_limit_bytes'],
                            'queued': sum(r['status'] == 'queued' for r in state['targets']),
                            'scanning': sum(r['status'] == 'scanning' for r in state['targets'])}
        (output / 'data/index.json.gz').write_bytes(gzip.compress(json.dumps(state, separators=(',', ':')).encode(), mtime=0))
        size = sum(p.stat().st_size for p in output.rglob('*') if p.is_file())
        if size >= config['site_limit_bytes']:
            raise ValueError(f'site capacity exceeded: {size} bytes; previous deployment retained')
        # Commit only after every referenced file is materialized and validated.
        save_state(repo, rel, state)
        print(json.dumps({'site_bytes': size, 'targets': len(state['targets'])}))


def cleanup(config: dict) -> None:
    repo = config['publishing_repository']
    rel = release(repo, 'current-reports')
    state = json.loads(rel['body'])
    keep = {r['asset'] for r in state['targets'] if r.get('asset')}
    for asset in pages(f"repos/{repo}/releases/{rel['id']}/assets"):
        if asset['name'].startswith('report-') and asset['name'] not in keep:
            api(f"repos/{repo}/releases/assets/{asset['id']}", method='DELETE')


def main() -> None:
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('command', choices=['scan', 'publish', 'cleanup'])
    p.add_argument('--config', type=Path, default=Path('config/code-analysis/service.json'))
    p.add_argument('--output', type=Path, default=Path('analysis-ui/dist'))
    p.add_argument('--refresh-target', help='Explicit current target ID, branch name, or PR #number to rescan')
    a = p.parse_args()
    config = load(a.config)
    if a.command == 'scan':
        scan(config, a.refresh_target)
    elif a.command == 'publish':
        publish(config, a.output)
    else:
        cleanup(config)


if __name__ == '__main__':
    main()
