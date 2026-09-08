"""Example source adapter: import a scanner-neutral JSON export from a selected tree.

Not enabled in production. Replace scanner-results.json collection with a real CLI
invocation or vendor API export, retaining exact revision verification.
"""
import argparse
import json
from pathlib import Path

p = argparse.ArgumentParser()
p.add_argument('--request', type=Path, required=True)
p.add_argument('--output', type=Path, required=True)
p.add_argument('--source', type=Path, required=True)
a = p.parse_args()
target = json.loads(a.request.read_text())['target']
source = a.source / 'scanner-results.json'
data = json.loads(source.read_text())
# Example input: {"source_repository":"owner/repo", "source_sha":"<40 SHA>",
# "status":"COMPLETED", "reason":"", "findings":[{"rule_id":"RULE-1",
# "message":"Explanation", "severity":"HIGH", "file":"src/main.py", "start_line":12}]}
if data['source_repository'] != target['source_repository'] or data['source_sha'] != target['head_sha']:
    raise ValueError('Export belongs to another revision')
a.output.write_text(json.dumps(data))
