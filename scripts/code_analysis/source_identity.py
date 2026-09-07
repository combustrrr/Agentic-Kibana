"""Validate dispatch identity; assemble only artifacts from this workflow attempt."""
import argparse
import json
import os
from pathlib import Path

from scripts.code_analysis.github_service import api, gh, extract_zip, pages
from scripts.code_analysis.hosted import target, write
from scripts.code_analysis.hosted_pipeline import assemble


def main():
    p = argparse.ArgumentParser()
    p.add_argument('--assemble', action='store_true')
    a = p.parse_args()
    row = json.loads(os.environ['TARGET_JSON'])
    validated = target(row['repository'], row['branch'], row['head_sha'], pr=row.get('pr'),
                       source_repository=row['source_repository'], base_sha=row.get('base_sha'), base_branch=row.get('base_branch'))
    if validated['id'] != row['id'] or os.environ['TOOLING_SHA'] != os.environ['GITHUB_SHA']:
        raise ValueError('dispatch identity or tooling revision mismatch')
    if not a.assemble:
        return
    host, run, attempt = os.environ['GITHUB_REPOSITORY'], os.environ['GITHUB_RUN_ID'], int(os.environ['GITHUB_RUN_ATTEMPT'])
    root = Path('.hosted/artifacts')
    root.mkdir(parents=True, exist_ok=True)
    # A rerun reuses its run ID; only artifacts created after this attempt started qualify.
    producer = api(f'repos/{host}/actions/runs/{run}/attempts/{attempt}')
    artifact_bytes = 0
    for artifact in pages(f'repos/{host}/actions/runs/{run}/artifacts', 'artifacts'):
        if artifact['expired'] or artifact['name'].startswith('hosted-report-') or artifact['created_at'] < producer['run_started_at']:
            continue
        destination = root / str(artifact['id'])
        artifact_bytes += artifact.get('size_in_bytes', 0)
        extract_zip(gh('api', f"repos/{host}/actions/artifacts/{artifact['id']}/zip", binary=True), destination)
    write(root / 'producer-status.json', {'scanner_family': 'Producer', 'run_id': run, 'run_attempt': attempt,
                                        'source_repository': row['source_repository'], 'source_sha': row['head_sha']})
    if row.get('pr'):
        from scripts.code_analysis.collect_coderabbit import collect
        try:
            evidence, status = collect(row['repository'], row['branch'], row['head_sha'], os.environ['GH_TOKEN'], pr_number=row['pr'])
            write(root / 'coderabbit/coderabbit-advisories.json', evidence)
            write(root / 'coderabbit/coderabbit-status.json', status)
        except Exception:
            write(root / 'coderabbit/coderabbit-status.json', {'scanner_family': 'CodeRabbit', 'status': 'NOT_AVAILABLE', 'reason': 'Exact upstream PR review collection failed'})
    else:
        write(root / 'coderabbit/coderabbit-status.json', {'scanner_family': 'CodeRabbit', 'status': 'NOT_APPLICABLE', 'reason': 'Branch target; CodeRabbit evidence is collected on PR targets'})
    report = assemble(root, Path('.hosted/output'), validated, host, run, Path('.source'), Path('config/code-analysis'))
    report.update(tooling_sha=os.environ['TOOLING_SHA'], producer_run_attempt=attempt,
                  producer_artifact_bytes=artifact_bytes, source_boundary='isolated-tooling-v1')
    write(Path('.hosted/output/report/report.json'), report)
    Path('.hosted/output/report').rename('.hosted/report')


if __name__ == '__main__':
    main()
