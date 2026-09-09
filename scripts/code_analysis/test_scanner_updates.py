import json
from pathlib import Path
import unittest

import yaml

from scripts.code_analysis import extensions


class ScannerUpdateTests(unittest.TestCase):
    def test_inventory_accepts_one_hundred_independent_extensions(self):
        example = json.loads(Path('config/code-analysis/scanner-extension.example.json').read_text())
        rows = [{**example, 'channel': f'ext-scanner-{i}', 'name': f'Independent scanner {i}'} for i in range(100)]
        manifest, catalog = extensions.contracts({'scanner_extensions': rows}, {'required_static_channels': []}, {'tools': []})
        self.assertEqual(len(manifest['required_static_channels']), 100)
        self.assertEqual(len(catalog['tools']), 100)

    def test_automerge_requires_native_compatibility_and_excludes_major_updates(self):
        policy = json.loads(Path('.github/renovate-scanners.json').read_text())
        self.assertFalse(policy['automerge'])
        self.assertFalse(policy['ignoreTests'])
        # Renovate removed requiredStatusChecks; enforce the named gate through
        # branch protection rather than a deprecated configuration key.
        updater = Path('.github/workflows/13-scanner-updates.yml').read_text()
        self.assertIn('protection/required_status_checks', updater)
        self.assertIn('Scanner compatibility', updater)
        self.assertNotIn('requiredStatusChecks', policy)
        for rule in policy['packageRules']:
            if rule.get('automerge'):
                self.assertEqual(rule['matchUpdateTypes'], ['patch'])
                self.assertLessEqual(set(rule['matchPackageNames']), {'bandit', 'ruff', 'radon', 'vulture', 'xenon'})
        workflow = yaml.safe_load(Path('.github/workflows/14-scanner-compatibility.yml').read_text())
        self.assertEqual(workflow['permissions'], {'contents': 'read'})
        self.assertNotIn('secrets.', json.dumps(workflow))
        self.assertIn('scanner_smoke', json.dumps(workflow))

    def test_bad_adapter_does_not_discard_a_healthy_sibling(self):
        import tempfile
        from scripts.code_analysis import hosted
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            row = json.loads(Path('config/code-analysis/scanner-extension.example.json').read_text())
            config = {'scanner_extensions': [row, {**row, 'channel': 'ext-second', 'name': 'Second'}]}
            identity = hosted.target('sample/repo', 'main', 'a' * 40)
            good = {'schema_version': 'channel-evidence-v1', 'channel': 'ext-second',
                    'source_repository': 'sample/repo', 'source_sha': 'a' * 40,
                    'target_id': identity['id'], 'producer_run_id': '1',
                    'status': 'COMPLETED', 'reason': '', 'findings': []}
            hosted.write(root/'ext-second.channel-evidence', good)
            hosted.write(root/'ext-example.channel-evidence', {**good, 'channel': 'ext-example', 'status': []})
            _, status = extensions.ingest(config, root, identity, '1')
            self.assertEqual(status['ext-example']['status'], 'INVALID_EVIDENCE')
            self.assertEqual(status['ext-second']['status'], 'COMPLETED')

    def test_malformed_registration_is_rejected_predictably(self):
        for row in [None, [], {'channel': []}]:
            with self.assertRaises(ValueError):
                extensions.registry({'scanner_extensions': [row]})
        example = json.loads(Path('config/code-analysis/scanner-extension.example.json').read_text())
        with self.assertRaises(ValueError):
            extensions.registry({'scanner_extensions': [{**example, 'name': 'Ruff'}]})

    def test_adapter_rerun_cannot_reuse_stale_result(self):
        import os
        import tempfile
        from types import SimpleNamespace
        from unittest.mock import patch
        from scripts.code_analysis import extension_runner as runner, hosted
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            row = json.loads(Path('config/code-analysis/scanner-extension.example.json').read_text())
            row['mode'] = 'vendor'
            hosted.write(root/'config/code-analysis/service.json', {'scanner_extensions': [row]})
            adapter = root/row['adapter']
            adapter.parent.mkdir(parents=True)
            adapter.write_text('')
            identity = hosted.target('sample/repo', 'main', 'a'*40)
            work = root/'.extension-output/ext-example'
            hosted.write(work/'adapter-result.json', {'source_repository': 'sample/repo', 'source_sha': 'a'*40,
                          'status': 'COMPLETED', 'reason': '', 'findings': []})
            with patch.object(runner, '__file__', str(root/'scripts/code_analysis/extension_runner.py')), \
                    patch.dict(os.environ, TARGET_JSON=json.dumps(identity), GITHUB_RUN_ID='1', TOOLING_SHA='b'*40, GITHUB_SHA='b'*40), \
                    patch.object(runner.subprocess, 'run', return_value=SimpleNamespace(returncode=0)):
                runner.run('ext-example')
            result = hosted.load(root/'.extension-output/ext-example.channel-evidence')
            self.assertEqual(result['status'], 'OPERATIONAL_FAILURE')

    def test_scorecard_update_cannot_keep_an_old_checksum(self):
        import io
        import shutil
        import tempfile
        from unittest.mock import patch
        from scripts.code_analysis.sync_scanner_workflows import sync
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root/'.ci').mkdir()
            (root/'.github/workflows').mkdir(parents=True)
            (root/'scripts/code_analysis').mkdir(parents=True)
            shutil.copy('.github/workflows/01-code-quality.yml', root/'.github/workflows')
            shutil.copy('scripts/code_analysis/generate_source_workflow.py', root/'scripts/code_analysis')
            pin = {'version': '9.0.0', 'checksum_version': '5.5.0', 'sha256': 'a'*64}
            path = root/'.ci/scorecard.json'
            path.write_text(json.dumps(pin))
            with patch('urllib.request.urlopen', return_value=io.BytesIO(b'wrong asset')), \
                    patch('subprocess.run') as execute:
                with self.assertRaises(ValueError): sync(root)
                execute.assert_not_called()
            self.assertEqual(json.loads(path.read_text()), pin)
            checksum = ('b'*64 + '  scorecard_9.0.0_linux_amd64.tar.gz\n').encode()
            with patch('urllib.request.urlopen', return_value=io.BytesIO(checksum)), patch('subprocess.run'):
                sync(root)
            self.assertEqual(json.loads(path.read_text())['sha256'], 'b'*64)
            self.assertEqual(json.loads(path.read_text())['checksum_version'], '9.0.0')


if __name__ == '__main__':
    unittest.main()
