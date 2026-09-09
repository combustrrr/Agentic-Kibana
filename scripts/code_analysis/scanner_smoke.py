"""Exercise the native output contracts eligible for automatic patch upgrades."""
import json
from pathlib import Path
import subprocess
import sys
import tempfile


def check(module, arguments, root, exits=(0, 1)):
    result = subprocess.run([sys.executable, '-m', module, *arguments], cwd=root,
                            capture_output=True, text=True, timeout=90)
    if result.returncode not in exits:
        raise RuntimeError(f'{module} invocation failed (exit {result.returncode})')
    return result.stdout


def main():
    with tempfile.TemporaryDirectory() as directory:
        root = Path(directory)
        (root / 'sample.py').write_text('def example(value):\n    unused_variable = 123\n    return eval(value)\n', encoding='utf-8')
        bandit = json.loads(check('bandit', ['-f', 'json', 'sample.py'], root))
        if not any(row['test_id'] == 'B307' for row in bandit['results']):
            raise RuntimeError('Bandit no longer reports the eval canary')
        ruff = json.loads(check('ruff', ['check', '--select', 'F841', '--output-format', 'json', 'sample.py'], root))
        if not any(row['code'] == 'F841' for row in ruff):
            raise RuntimeError('Ruff no longer reports the unused-variable canary')
        radon = json.loads(check('radon', ['cc', '-j', 'sample.py'], root))
        if not radon['sample.py'] or type(radon['sample.py'][0]['complexity']) is not int:
            raise RuntimeError('Radon native complexity contract changed')
        vulture = check('vulture', ['sample.py', '--min-confidence', '60'], root, exits=(0, 1, 3))
        if 'unused_variable' not in vulture:
            raise RuntimeError('Vulture no longer reports the unused-variable canary')
        check('xenon', ['--max-absolute', 'A', '--max-modules', 'A', '--max-average', 'A', 'sample.py'], root, exits=(0,))
    print('Native scanner compatibility passed: Bandit, Ruff, Radon, Vulture, Xenon')


if __name__ == '__main__':
    main()
