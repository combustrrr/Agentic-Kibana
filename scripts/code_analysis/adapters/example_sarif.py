"""Example source adapter for a SARIF 2.1 export; no scanner is enabled by this file."""
import argparse
import json
from pathlib import Path

p = argparse.ArgumentParser()
p.add_argument('--request', type=Path, required=True)
p.add_argument('--output', type=Path, required=True)
p.add_argument('--source', type=Path, required=True)
a = p.parse_args()
target = json.loads(a.request.read_text())['target']
sarif = json.loads((a.source / 'scanner-results.sarif').read_text())
if sarif.get('version') != '2.1.0' or not isinstance(sarif.get('runs'), list):
    raise ValueError('Expected SARIF 2.1.0')
findings = []
for run in sarif['runs']:
    if any(invocation.get('executionSuccessful') is False for invocation in run.get('invocations', [])):
        raise ValueError('Scanner execution failed')
    for result in run.get('results', []):
        location = result['locations'][0]['physicalLocation']
        findings.append({'rule_id': result['ruleId'], 'message': result['message']['text'],
                         'severity': {'error':'HIGH', 'warning':'MEDIUM', 'note':'LOW', 'none':'INFO'}[result.get('level', 'warning')],
                         'file': location['artifactLocation']['uri'],
                         'start_line': location.get('region', {}).get('startLine', 0),
                         'tool_version': run.get('tool', {}).get('driver', {}).get('version', '')})
# A real adapter must run the scanner against --source here, or verify the export's
# native commit metadata. This example requires an adjacent attribution sidecar.
metadata = json.loads((a.source / 'scanner-results.identity.json').read_text())
if metadata.get('source_repository') != target['source_repository'] or metadata.get('source_sha') != target['head_sha']:
    raise ValueError('Export source identity mismatch')
a.output.write_text(json.dumps({**metadata, 'status':'COMPLETED', 'reason':'', 'findings':findings}))
