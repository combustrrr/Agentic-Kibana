"""Scan an explicit manifest profile; never invoke arbitrary project build tools."""
import json
import os
from pathlib import Path
import subprocess
import tempfile
import re


def main():
    config = json.loads((Path(__file__).resolve().parents[2] / 'config/code-analysis/service.json').read_text())
    profile = config['profile']
    repository = os.environ.get('SOURCE_REPOSITORY', config['source_repository'])
    if not re.fullmatch(r'[\w.-]+/[\w.-]+', repository):
        raise ValueError('Invalid source repository for Snyk attribution')
    root = Path.cwd().resolve()
    runs, failures = [], []
    # Node and Python can choose different OS temp roots. Use one explicit
    # trusted staging directory so the isolated resolver can validate its path.
    staging = Path(os.environ['RUNNER_TEMP']) / 'snyk-resolver-staging'
    staging.mkdir(exist_ok=True)
    environment = {**os.environ, 'SNYK_TMP_PATH': str(staging), 'TMPDIR': str(staging)}
    with tempfile.TemporaryDirectory(prefix='snyk-scan-') as directory:
        for number, name in enumerate(profile['snyk_python_manifests'] + profile['snyk_npm_manifests']):
            path = (root / name).resolve(strict=True)
            if not path.is_relative_to(root):
                raise ValueError('manifest escapes checkout')
            output = Path(directory) / f'{number}.sarif'
            command = ['snyk', 'test', '--file=' + name, '--sarif-file-output=' + str(output),
                       '--remote-repo-url=https://github.com/' + repository]
            if name in profile['snyk_python_manifests']:
                command += ['--command=' + str(Path(os.environ['RUNNER_TEMP']) / 'snyk-metadata/inspect-python')]
            result = subprocess.run(command, check=False, env=environment)
            if result.returncode > 1 or not output.is_file():
                failures.append(name)
            if output.is_file():
                runs.extend(json.loads(output.read_text())['runs'])
    Path('snyk-open-source.sarif').write_text(json.dumps({'version': '2.1.0', 'runs': runs}), encoding='utf-8')
    if failures:
        print('Incomplete dependency manifests: ' + ', '.join(failures))
        raise SystemExit(2)


if __name__ == '__main__':
    main()
