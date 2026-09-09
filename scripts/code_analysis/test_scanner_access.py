import io
import json
import unittest
import urllib.error
import os
from pathlib import Path
import subprocess
import sys
import tempfile
from unittest.mock import patch

import yaml
from scripts.code_analysis import probe_sonar_access as probe
from scripts.code_analysis.generate_source_workflow import generate, diagnostics


class ScannerAccessTests(unittest.TestCase):
    def test_vendor_diagnostics_cannot_publish_a_target_report(self):
        workflow = yaml.safe_load(diagnostics())
        self.assertEqual(set(workflow['jobs']), {'identity', 'scanner-3-snyk', 'scanner-1-sonarqube-cloud'})
        self.assertEqual(workflow['permissions'], {'contents': 'read'})
        self.assertNotIn('--assemble', diagnostics())
        self.assertEqual(Path('.github/workflows/12-scanner-diagnostics.yml').read_text(encoding='utf-8'), diagnostics())

    def test_snyk_resolver_imports_its_helpers_without_importing_source(self):
        from scripts.code_analysis.snyk_python import resolver_path
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            source, staged = root/'source', root/'staged'
            source.mkdir(); staged.mkdir()
            (source/'sitecustomize.py').write_text('raise RuntimeError("source imported")')
            (staged/'sibling.py').write_text('value="trusted resolver helper"')
            script = staged/'pip_resolve.py'
            script.write_text('import sibling; print(sibling.value)')
            helper = Path('scripts/code_analysis/snyk_python.py').resolve()
            result = subprocess.run([sys.executable,'-I',str(helper),str(source),str(script)], cwd=source,
                                    env={**os.environ,'PYTHONPATH':str(source)},capture_output=True,text=True)
            self.assertEqual(result.returncode,0,result.stderr)
            self.assertIn('trusted resolver helper',result.stdout)
            bad = source/'pip_resolve.py'; bad.write_text('')
            with self.assertRaises(ValueError): resolver_path(str(bad),source)

    def test_branch_entitlement_is_distinct_from_token_failure(self):
        for message, kind in [('Organization is not allowed to access data from non main branches.', 'branch_entitlement'), ('private provider data', 'access_denied')]:
            error = urllib.error.HTTPError('https://sonarcloud.io', 403, 'Forbidden', {}, io.BytesIO(json.dumps({'errors':[{'msg':message}]}).encode()))
            with patch.object(probe.urllib.request, 'urlopen', side_effect=error):
                status, document = probe._request('https://sonarcloud.io', 'do-not-log')
            self.assertEqual(status, 403)
            self.assertEqual(document, {'access_failure':kind})
            self.assertNotIn(message, json.dumps(document))

    def test_probe_uses_the_actual_scanner_branch_after_identity_derivation(self):
        job = yaml.safe_load(generate())['jobs']['scanner-1-sonarqube-cloud']
        steps = job['steps']
        identity = next(i for i,s in enumerate(steps) if s.get('id')=='sonar-identity')
        access = next(i for i,s in enumerate(steps) if s.get('id')=='sonar-access')
        self.assertLess(identity, access)
        self.assertEqual(steps[access]['env']['SCAN_BRANCH'], '${{ steps.sonar-identity.outputs.sonar_branch }}')
        status = next(s for s in steps if s.get('name')=='Record configured scan status')
        self.assertIn('branch_entitlement', status['run'])


if __name__ == '__main__':
    unittest.main()
