"""Synchronize generated scanner workflows after dependency bot changes."""
import re
import json
from pathlib import Path
import subprocess
import sys
import urllib.request

import yaml


def sync(root: Path):
    pin_path = root / '.ci/scorecard.json'
    pin = json.loads(pin_path.read_text())
    version = pin['version']
    if not re.fullmatch(r'\d+\.\d+\.\d+', version):
        raise ValueError('Invalid Scorecard version')
    if pin['checksum_version'] != version:
        url = f'https://github.com/ossf/scorecard/releases/download/v{version}/scorecard_checksums.txt'
        with urllib.request.urlopen(url, timeout=30) as response:
            checksums = response.read(1_000_001)
        if len(checksums) > 1_000_000:
            raise ValueError('Oversized release checksum file')
        pattern = rf'^([0-9a-f]{{64}})\s+\*?scorecard_{re.escape(version)}_linux_amd64\.tar\.gz$'
        matches = re.findall(pattern, checksums.decode('utf-8'), flags=re.M)
        if len(matches) != 1:
            raise ValueError('Missing or ambiguous official release checksum')
        pin.update(sha256=matches[0], checksum_version=version)
        pin_path.write_text(json.dumps(pin, indent=2) + '\n')
    document = yaml.safe_load((root / '.github/workflows/01-code-quality.yml').read_text(encoding='utf-8'))
    actions = {}
    for job in document['jobs'].values():
        for step in job.get('steps', []):
            action = step.get('uses', '')
            if '@' in action:
                name, digest = action.split('@', 1)
                if not re.fullmatch('[0-9a-f]{40}', digest):
                    raise ValueError('Action updates must remain immutable')
                if name in actions and actions[name] != action:
                    raise ValueError('Conflicting action revisions in source workflow')
                actions[name] = action
    path = root / 'scripts/code_analysis/generate_source_workflow.py'
    content = path.read_text(encoding='utf-8')
    for constant, name in [('CHECKOUT', 'actions/checkout'), ('UPLOAD', 'actions/upload-artifact'), ('PYTHON', 'actions/setup-python')]:
        content, count = re.subn(rf"^{constant} = '[^']+'$", f"{constant} = '{actions[name]}'", content, flags=re.M)
        if count != 1:
            raise ValueError('Missing generator action constant')
    path.write_text(content, encoding='utf-8')
    subprocess.run([sys.executable, '-m', 'scripts.code_analysis.generate_source_workflow'], cwd=root, check=True)


if __name__ == '__main__':
    sync(Path(__file__).resolve().parents[2])
