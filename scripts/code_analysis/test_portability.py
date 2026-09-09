import json
from pathlib import Path
import tempfile
import unittest

import yaml
from scripts.code_analysis.configure_instance import configure, bundle
from scripts.code_analysis.applicability import selection, PORTABLE_JOBS
from scripts.code_analysis.generate_source_workflow import generate
from scripts.code_analysis.hosted import load


class PortabilityTests(unittest.TestCase):
    def config(self):
        return configure(load(Path('config/code-analysis/service.json')), 'example/source', 'example/scanners',
                         'example/dashboard', 'main', {'mode': 'portable'})

    def test_unrelated_layouts_do_not_require_python_or_javascript(self):
        for files in (['src/main.rs', 'Cargo.toml'], ['Main.java', 'pom.xml'], ['index.js', 'package.json'], ['README.md']):
            with self.subTest(files=files), tempfile.TemporaryDirectory() as directory:
                root = Path(directory)
                for name in files:
                    path = root / name
                    path.parent.mkdir(parents=True, exist_ok=True)
                    path.touch()
                jobs, excluded, _ = selection(self.config(), root)
                self.assertEqual(set(jobs), PORTABLE_JOBS)
                self.assertEqual(excluded['atheris']['status'], 'NOT_AVAILABLE')
                self.assertNotIn('DEFERRED', {v['status'] for v in excluded.values()})

    def test_portable_workflow_contains_no_original_project_harness(self):
        workflow = generate(self.config())
        jobs = yaml.safe_load(workflow)['jobs']
        for name in ('backend/', 'webui/', 'combustrrr', 'ARYDESTROYER', 'agentic-soc-backend'):
            self.assertNotIn(name, workflow)
        self.assertNotIn('scanner-7-atheris-state-machine', jobs)
        self.assertIn(' --output=semgrep-results.json .', workflow)
        self.assertEqual(jobs['scanner-3-gitleaks']['permissions'], {'contents':'read'})

    def test_current_workflow_is_unchanged(self):
        self.assertEqual(generate(), Path('.github/workflows/11-source-analysis.yml').read_text(encoding='utf-8'))

    def test_bundle_synchronizes_all_services_without_overwriting(self):
        with tempfile.TemporaryDirectory() as directory:
            destination = Path(directory) / 'new'
            args = (self.config(), destination, 'https://new-worker.example', 'https://example.github.io/dashboard/', 'Iv-test', 'new-launcher')
            bundle(*args)
            a = load(destination / 'analysis/config/code-analysis/service.json')
            b = load(destination / 'dashboard/config/code-analysis/service.json')
            launcher = load(destination / 'launcher/wrangler.jsonc')
            self.assertEqual(a, b)
            self.assertEqual(a['source_repository'], launcher['vars']['SOURCE_REPOSITORY'])
            self.assertEqual(launcher['vars']['DASHBOARD_ORIGIN'], 'https://example.github.io')
            self.assertNotIn('combustrrr', json.dumps(launcher))
            with self.assertRaises(FileExistsError):
                bundle(*args)

    def test_colliding_repositories_and_invalid_origins_are_rejected(self):
        template = load(Path('config/code-analysis/service.json'))
        with self.assertRaises(ValueError):
            configure(template, 'Owner/Repo', 'owner/repo', 'owner/site', 'main', {'mode':'portable'})
        with tempfile.TemporaryDirectory() as directory, self.assertRaises(ValueError):
            bundle(self.config(), Path(directory)/'new', 'https://user:password@worker.example', 'https://example.github.io', 'id', 'worker')


if __name__ == '__main__':
    unittest.main()
