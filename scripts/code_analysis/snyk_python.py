"""Allow Snyk's staged resolver imports while keeping source off Python's import path."""
import os
from pathlib import Path
import runpy
import subprocess
import sys
import tempfile
import json
import traceback


def resolver_path(argument: str, source: Path) -> Path:
    script = Path(argument).resolve(strict=True)
    temporary = Path(tempfile.gettempdir()).resolve()
    if (script.name != 'pip_resolve.py' or not script.is_file()
            or not script.is_relative_to(temporary) or script.is_relative_to(source.resolve())):
        raise ValueError('Only the Snyk resolver staged outside the source checkout is allowed')
    return script


def main():
    source, arguments = Path(sys.argv[1]), sys.argv[2:]
    if not arguments or arguments[0].startswith('-'):
        # CLI interpreter probes retain fully isolated Python behavior.
        raise SystemExit(subprocess.call([sys.executable, '-I', *arguments]))
    script = resolver_path(arguments[0], source)
    sys.path.insert(0, str(script.parent))
    sys.argv = [str(script), *arguments[1:]]
    runpy.run_path(str(script), run_name='__main__')


if __name__ == '__main__':
    try:
        main()
    except Exception as error:
        # Only exception type and trusted stack locations, never environment values
        # or arbitrary source/provider error text, enter diagnostic artifacts.
        diagnostic = {'error_type': type(error).__name__,
                      'frames': [{'file': frame.filename, 'line': frame.lineno, 'function': frame.name}
                                 for frame in traceback.extract_tb(error.__traceback__)]}
        path = Path(os.environ['RUNNER_TEMP']) / 'snyk-resolver-error.json'
        path.write_text(json.dumps(diagnostic), encoding='utf-8')
        raise
