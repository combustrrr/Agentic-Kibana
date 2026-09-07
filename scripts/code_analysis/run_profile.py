"""Execute trusted repository-profile commands in an unprivileged scanner job."""
import argparse
import os
import subprocess
import sys
from pathlib import Path

from scripts.code_analysis.hosted import load, write


def main():
    p = argparse.ArgumentParser()
    p.add_argument('task', choices=['python-install', 'python-test', 'javascript-install', 'api'])
    p.add_argument('--source', type=Path, required=True)
    a = p.parse_args()
    profile = load(Path(__file__).resolve().parents[2] / 'config/code-analysis/service.json')['profile']
    root = a.source.resolve(strict=True)
    cwd = root / profile['javascript_root' if a.task.startswith('javascript') else 'python_root']
    if not cwd.resolve().is_relative_to(root):
        raise ValueError('profile working directory escapes source checkout')
    # Source installs/tests do not inherit job credentials, even if this helper is
    # accidentally called from a token-bearing step in the future.
    env = {k: v for k, v in os.environ.items() if not any(s in k.upper() for s in ('TOKEN', 'SECRET', 'PASSWORD', 'CREDENTIAL'))}
    if a.task == 'python-install':
        command = [sys.executable, '-m', 'pip', 'install', '-r', str(root / profile['python_requirements'])]
        development = profile.get('python_development_requirements')
        if development:
            command += ['-r', str(root / development)]
    else:
        command = profile[{'python-test': 'python_test_command', 'javascript-install': 'javascript_install_command', 'api': 'api_command'}[a.task]]
    result = subprocess.run(command, cwd=cwd, env=env, check=False)
    if a.task == 'python-test':
        measured = (cwd / 'coverage.json').is_file()
        write(cwd / 'coverage-status.json', {'schema_version': '1', 'scanner_family': 'Coverage.py',
              'status': 'COMPLETED' if measured else 'OPERATIONAL_FAILURE', 'test_exit_code': result.returncode,
              'reason': f'Test exit={result.returncode}; coverage output ' + ('retained' if measured else 'missing')})
        return
    raise SystemExit(result.returncode)


if __name__ == '__main__':
    main()
