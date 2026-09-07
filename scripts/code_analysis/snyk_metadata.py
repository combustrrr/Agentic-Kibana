"""Resolve wheel metadata for Snyk without installing or executing source packages.

Only ordinary index requirements are accepted. pip resolves binary wheels in a
temporary directory; only dist-info METADATA enters the inspection environment.
No wheel code, entry points, .pth files, setup.py, or repository scripts run.
"""
import argparse
from email.message import Message
import json
import os
from pathlib import Path
import re
import subprocess
import sys
import tempfile
import venv

from pip._vendor.packaging.requirements import Requirement


def requirements(path: Path) -> list[str]:
    result = []
    for line in path.read_text(encoding='utf-8').splitlines():
        line = line.split(' #', 1)[0].strip()
        if not line or line.startswith('#'):
            continue
        value = Requirement(line)
        if value.url or line.startswith('-'):
            raise ValueError('Snyk metadata resolution supports index requirements only')
        result.append(str(value))
    return result


def metadata(item: dict) -> tuple[str, str]:
    name, version = item['name'], item['version']
    if not re.fullmatch(r'[A-Za-z0-9_.-]+', name) or not re.fullmatch(r'[A-Za-z0-9_.+!-]+', version):
        raise ValueError('invalid wheel metadata identity')
    msg = Message()
    msg['Metadata-Version'] = '2.1'
    msg['Name'], msg['Version'] = name, version
    for dependency in item.get('requires_dist', []):
        msg['Requires-Dist'] = str(Requirement(dependency))
    return re.sub('[-.]', '_', name) + '-' + version + '.dist-info', msg.as_string()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--source', type=Path, required=True)
    parser.add_argument('--destination', type=Path, required=True)
    args = parser.parse_args()
    root = args.source.resolve()
    profile = json.loads((Path(__file__).resolve().parents[2] / 'config/code-analysis/service.json').read_text())['profile']
    lines = []
    for name in profile['snyk_python_manifests']:
        path = (root / name).resolve(strict=True)
        if not path.is_relative_to(root):
            raise ValueError('manifest escapes checkout')
        lines.extend(requirements(path))
    env = {k: v for k, v in os.environ.items() if not any(s in k.upper() for s in ('TOKEN', 'SECRET', 'PASSWORD', 'CREDENTIAL', 'PYTHONPATH'))}
    with tempfile.TemporaryDirectory(prefix='snyk-metadata-') as directory:
        work = Path(directory)
        (work / 'requirements.txt').write_text('\n'.join(lines), encoding='utf-8')
        subprocess.run([sys.executable, '-I', '-m', 'pip', '--isolated', 'install', '--dry-run',
                        '--ignore-installed', '--only-binary=:all:', '--report', str(work / 'report.json'),
                        '-r', str(work / 'requirements.txt')], cwd=work, env=env, check=True)
        packages = json.loads((work / 'report.json').read_text())['install']
    destination = args.destination.resolve()
    venv.create(destination, with_pip=True)
    python = destination / 'bin/python'
    site = subprocess.check_output([str(python), '-I', '-c', 'import sysconfig; print(sysconfig.get_path("purelib"))'], env=env, text=True).strip()
    for item in packages:
        directory, content = metadata(item['metadata'])
        path = Path(site) / directory
        path.mkdir(exist_ok=True)
        (path / 'METADATA').write_text(content, encoding='utf-8')
    wrapper = destination / 'inspect-python'
    wrapper.write_text('#!/bin/sh\nexec "' + str(python) + '" -I "$@"\n', encoding='utf-8')
    wrapper.chmod(0o755)
    print(json.dumps({'metadata_distributions': len(packages)}))


if __name__ == '__main__':
    main()
