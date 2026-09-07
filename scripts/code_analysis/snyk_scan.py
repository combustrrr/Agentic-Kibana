"""Scan an explicit manifest profile; never invoke arbitrary project build tools."""
import json
import os
from pathlib import Path
import subprocess
import tempfile


def main():
    profile = json.loads((Path(__file__).resolve().parents[2] / 'config/code-analysis/service.json').read_text())['profile']
    root = Path.cwd().resolve()
    runs, failures = [], []
    with tempfile.TemporaryDirectory(prefix='snyk-scan-') as directory:
        for number, name in enumerate(profile['snyk_python_manifests'] + profile['snyk_npm_manifests']):
            path = (root / name).resolve(strict=True)
            if not path.is_relative_to(root):
                raise ValueError('manifest escapes checkout')
            output = Path(directory) / f'{number}.sarif'
            command = ['snyk', 'test', '--file=' + name, '--sarif-file-output=' + str(output)]
            if name in profile['snyk_python_manifests']:
                command += ['--command=' + str(Path(os.environ['RUNNER_TEMP']) / 'snyk-metadata/inspect-python')]
            result = subprocess.run(command, check=False)
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
