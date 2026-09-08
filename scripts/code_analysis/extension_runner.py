"""Execute one trusted adapter; scanner installation/API access belongs in that adapter."""
from __future__ import annotations

import argparse
import json
import os
import subprocess
import sys
from pathlib import Path

from scripts.code_analysis.extensions import registry
from scripts.code_analysis.hosted import load, write


def run(channel: str) -> None:
    root = Path(__file__).resolve().parents[2]
    row = next(r for r in registry(load(root / 'config/code-analysis/service.json')) if r['channel'] == channel)
    target = json.loads(os.environ['TARGET_JSON'])
    output = root / '.extension-output'
    output.mkdir(exist_ok=True)
    request = output / 'request.json'
    result = output / 'adapter-result.json'
    write(request, {'target': target, 'producer_run_id': os.environ['GITHUB_RUN_ID']})
    envelope = {'schema_version': 'channel-evidence-v1', 'channel': channel,
                'source_repository': target['source_repository'], 'source_sha': target['head_sha'],
                'target_id': target['id'], 'producer_run_id': os.environ['GITHUB_RUN_ID'],
                'status': 'OPERATIONAL_FAILURE', 'reason': 'Adapter did not produce usable evidence', 'findings': []}
    try:
        adapter = (root / row['adapter']).resolve()
        if not adapter.is_relative_to(root) or not adapter.is_file():
            raise ValueError('Missing trusted adapter')
        if os.environ['TOOLING_SHA'] != os.environ['GITHUB_SHA']:
            raise ValueError('Tooling identity mismatch')
        command = [sys.executable, '-I', str(adapter), '--request', str(request), '--output', str(result)]
        if row['mode'] == 'source':
            source = root / '.source'
            sha = subprocess.check_output(['git', '-C', str(source), 'rev-parse', 'HEAD'], text=True).strip()
            if sha != target['head_sha']:
                raise ValueError('Source checkout mismatch')
            command += ['--source', str(source)]
        # Do not retain arbitrary scanner output in public workflow logs.
        completed = subprocess.run(command, cwd=output, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                                   timeout=row.get('timeout_minutes', 15) * 60)
        if completed.returncode or result.is_symlink() or result.stat().st_size > 50_000_000:
            raise ValueError('Adapter execution failed')
        value = load(result)
        # Vendor adapters must verify the native export's revision, not relabel a latest response.
        if value.get('source_repository') != target['source_repository'] or value.get('source_sha') != target['head_sha']:
            raise ValueError('Adapter source attribution mismatch')
        envelope.update({k: value[k] for k in ('status', 'reason', 'findings')})
    except (OSError, ValueError, KeyError, TypeError, subprocess.SubprocessError):
        pass
    write(output / (channel + '.channel-evidence'), envelope)


if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument('channel')
    run(parser.parse_args().channel)
