"""Trusted scanner registration and versioned, exact-producer evidence ingestion."""
from __future__ import annotations

import copy
import json
import re
from pathlib import Path

from scripts.code_analysis.hosted import safe_file

CLASSES = {'code', 'security', 'dependencies', 'infrastructure', 'reliability'}
STATUSES = {'COMPLETED', 'POLICY_FINDINGS', 'OPERATIONAL_FAILURE', 'NOT_AVAILABLE', 'NOT_APPLICABLE'}


def registry(config: dict) -> list[dict]:
    rows = config.get('scanner_extensions', [])
    if not isinstance(rows, list):
        raise ValueError('scanner_extensions must be an array')
    ids, families = set(), set()
    from scripts.code_analysis.monitoring import scanner_family
    catalog_path = Path(__file__).resolve().parents[2] / 'config/code-analysis/proposal-tool-catalog.json'
    builtins = {item['tool'] for item in json.loads(catalog_path.read_text(encoding='utf-8'))['tools']}
    for row in rows:
        if not isinstance(row, dict):
            raise ValueError('Each scanner extension must be an object')
        channel = row.get('channel', '')
        if not isinstance(channel, str) or not re.fullmatch(r'ext-[a-z0-9][a-z0-9-]{0,45}', channel) or channel in ids:
            raise ValueError('Extension channels require unique ext- identifiers')
        ids.add(channel)
        family = row.get('name')
        if not isinstance(family, str) or not family.strip() or family in families:
            raise ValueError('Extension names must be unique and nonempty')
        if family in builtins or scanner_family(family) != family:
            raise ValueError('Extension name collides with a built-in scanner or alias')
        families.add(family)
        if not isinstance(row.get('class'), str) or not isinstance(row.get('mode'), str) or row['class'] not in CLASSES or row['mode'] not in {'source', 'vendor'}:
            raise ValueError('Extension requires a supported class and source/vendor mode')
        if not isinstance(row.get('adapter'), str) or not safe_file(row['adapter']) or not row['adapter'].startswith('scripts/code_analysis/adapters/') or not row['adapter'].endswith('.py'):
            raise ValueError('Adapters must be trusted Python files under scripts/code_analysis/adapters')
        if type(row.get('timeout_minutes', 15)) is not int or not 1 <= row.get('timeout_minutes', 15) <= 60:
            raise ValueError('Adapter timeout must be 1..60 minutes')
        if row.get('secrets') and row['mode'] != 'vendor':
            raise ValueError('Source-executing adapters cannot receive vendor credentials')
        if not isinstance(row.get('secrets', {}), dict):
            raise ValueError('Extension secrets must be an object')
        for env, secret in row.get('secrets', {}).items():
            if not isinstance(env, str) or not isinstance(secret, str) or not re.fullmatch(r'[A-Z][A-Z0-9_]*', env) or not re.fullmatch(r'[A-Z][A-Z0-9_]*', secret):
                raise ValueError('Invalid vendor credential mapping')
            if env in {'PATH', 'PYTHONPATH', 'PYTHONHOME', 'TARGET_JSON', 'TOOLING_SHA', 'GITHUB_SHA', 'GITHUB_TOKEN', 'GH_TOKEN'}:
                raise ValueError('Reserved adapter environment variable')
        if row.get('deferred_reason') is not None and not str(row['deferred_reason']).strip():
            raise ValueError('Deferral requires a reason')
        if not isinstance(row.get('evidence_source', 'DETERMINISTIC'), str) or row.get('evidence_source', 'DETERMINISTIC') not in {'DETERMINISTIC', 'AI_ADVISORY'}:
            raise ValueError('Invalid evidence lane')
    return rows


def contracts(config: dict, manifest: dict, catalog: dict) -> tuple[dict, dict]:
    manifest, catalog = copy.deepcopy(manifest), copy.deepcopy(catalog)
    from scripts.code_analysis.monitoring import scanner_family
    for row in registry(config):
        if scanner_family(row['name']) != row['name']:
            raise ValueError('Extension name collides with a built-in scanner alias')
        if any(t['channel'] == row['channel'] or t['tool'] == row['name'] for t in catalog['tools']):
            raise ValueError('Extension collides with an existing scanner')
        manifest['required_static_channels'].append({
            'channel': row['channel'], 'scanner_family': row['name'], 'surface': row['class'],
            'workflow': '11-source-analysis.yml', 'artifact_patterns': [row['channel'] + '.channel-evidence']})
        catalog['tools'].append({'channel': row['channel'], 'tool': row['name'], 'class': row['class'],
                                 'surface': row['class'], 'workflow': '11-source-analysis.yml',
                                 'evidence_source': row.get('evidence_source', 'DETERMINISTIC')})
    return manifest, catalog


def ingest(config: dict, artifacts: Path, identity: dict, run_id: str) -> tuple[list, dict]:
    findings, statuses = [], {}
    for row in registry(config):
        channel = row['channel']
        status = {'status': 'NOT_AVAILABLE', 'reason': 'No evidence from this exact producer'}
        if row.get('deferred_reason'):
            statuses[channel] = {'status': 'DEFERRED', 'reason': row['deferred_reason']}
            continue
        files = list(artifacts.rglob(channel + '.channel-evidence'))
        try:
            if len(files) != 1:
                raise ValueError('Expected exactly one scanner evidence envelope')
            path = files[0]
            if path.is_symlink() or path.stat().st_size > 50_000_000:
                raise ValueError('Unsafe or oversized scanner envelope')
            envelope = json.loads(path.read_text(encoding='utf-8'))
            if not isinstance(envelope, dict):
                raise ValueError('Invalid scanner envelope')
            if (envelope.get('schema_version') != 'channel-evidence-v1' or envelope.get('channel') != channel
                    or envelope.get('source_repository') != identity['source_repository']
                    or envelope.get('source_sha') != identity['head_sha']
                    or envelope.get('target_id') != identity['id']
                    or str(envelope.get('producer_run_id')) != str(run_id)):
                raise ValueError('Scanner evidence identity mismatch')
            if not isinstance(envelope.get('status'), str) or envelope['status'] not in STATUSES or not isinstance(envelope.get('findings'), list):
                raise ValueError('Invalid scanner result status/findings')
            if envelope['status'] not in {'COMPLETED', 'POLICY_FINDINGS'} and envelope['findings']:
                raise ValueError('Incomplete adapter results cannot claim complete findings')
            if envelope['status'] != 'COMPLETED' and not envelope.get('reason'):
                raise ValueError('Non-complete status requires an explanation')
            if not isinstance(envelope.get('reason', ''), str):
                raise ValueError('Invalid scanner explanation')
            pending = []
            for finding in envelope['findings']:
                if not isinstance(finding, dict):
                    raise ValueError('Invalid scanner finding')
                if (not isinstance(finding.get('severity'), str) or finding['severity'] not in {'CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'INFO', 'UNKNOWN'}
                        or not isinstance(finding.get('message'), str) or not isinstance(finding.get('rule_id'), str) or not finding['rule_id'].strip()
                        or not safe_file(finding.get('file', ''))
                        or type(finding.get('start_line')) is not int or finding['start_line'] < 0):
                    raise ValueError('Invalid finding rule, severity or source location')
                clean = {key: finding[key] for key in ('message', 'severity', 'rule_id', 'file', 'start_line',
                         'native_result_id', 'tool_version', 'ruleset_version') if key in finding}
                if any(not isinstance(clean[key], str) for key in ('native_result_id', 'tool_version', 'ruleset_version') if key in clean):
                    raise ValueError('Scanner version and native identity must be text')
                clean.update(source_tool=row['name'], category='QUALITY',
                             evidence_source=row.get('evidence_source', 'DETERMINISTIC'),
                             raw_artifact=path.relative_to(artifacts).as_posix())
                # Withhold potentially sensitive adapter text before canonicalization.
                if row.get('sensitive'):
                    clean.update(message='Potential secret detected; value withheld from public report.',
                                 rule_concept='hardcoded-secret', rule_id='potential-secret')
                    clean.pop('native_result_id', None)
                pending.append(clean)
            findings.extend(pending)
            status = {'status': envelope['status'], 'reason': str(envelope.get('reason', ''))}
        except (ValueError, KeyError, TypeError, OSError, RecursionError):
            status = {'status': 'INVALID_EVIDENCE', 'reason': 'Missing, malformed or mixed-revision adapter evidence'}
        statuses[channel] = status
    return findings, statuses
