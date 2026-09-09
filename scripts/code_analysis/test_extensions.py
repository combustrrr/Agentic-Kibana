"""Extension acceptance: identity, partial evidence, secrets and generated jobs."""
import copy
import json
import shutil
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from scripts.code_analysis import extensions as e, hosted as h
from scripts.code_analysis.monitoring import canonicalize, build_snapshot
from scripts.code_analysis.snapshot import build_analysis_snapshot


class ExtensionTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.extension = h.load(Path('config/code-analysis/scanner-extension.example.json'))
        self.config = {'scanner_extensions': [self.extension]}
        self.identity = h.target('another/project', 'develop', 'a' * 40)
        self.envelope = {'schema_version': 'channel-evidence-v1', 'channel': 'ext-example',
                         'source_repository': 'another/project', 'source_sha': 'a' * 40,
                         'target_id': self.identity['id'], 'producer_run_id': '123',
                         'status': 'COMPLETED', 'reason': '', 'findings': []}

    def ingest(self):
        h.write(self.root / 'ext-example.channel-evidence', self.envelope)
        return e.ingest(self.config, self.root, self.identity, '123')

    def test_zero_failure_malformed_and_mixed_revision_are_distinct(self):
        self.assertEqual(self.ingest()[1]['ext-example']['status'], 'COMPLETED')
        self.envelope.update(status='OPERATIONAL_FAILURE', reason='Unavailable vendor access')
        self.assertEqual(self.ingest()[1]['ext-example']['status'], 'OPERATIONAL_FAILURE')
        for key, value in [('source_sha', 'b'*40), ('producer_run_id', '124'), ('target_id', 'foreign')]:
            old = self.envelope[key]
            self.envelope[key] = value
            self.assertEqual(self.ingest()[1]['ext-example']['status'], 'INVALID_EVIDENCE')
            self.envelope[key] = old

    def test_new_channel_flows_to_hosted_report_without_ui_changes(self):
        self.envelope['findings'] = [{'rule_id':'RULE-1', 'message':'Example finding', 'severity':'HIGH',
                                     'file':'src/example.rs', 'start_line':4}]
        raw, status = self.ingest()
        manifest, catalog = e.contracts(self.config, {'schema_version':'1','required_static_channels':[]}, {'tools':[]})
        current = canonicalize(raw, 'another/project', {'commit_sha':'a'*40,'branch':'develop',
                              'workflow_run_id':'123','generated_at':'2026-09-08T00:00:00Z'}, manifest)
        gate = {'channels':[{**manifest['required_static_channels'][0], **status['ext-example'], 'artifact_files':[]}]}
        proof = {'commit_sha':'a'*40,'workflow_run_ids':['123'], 'artifact_hashes':[{'path':'ext-example.channel-evidence','sha256':'c'*64}]}
        snapshot = build_analysis_snapshot(build_snapshot(current, gate, proof, allow_partial=True), catalog, self.root)
        report = h.build(snapshot, self.identity, self.root/'report', producer_repository='observer/host')
        self.assertEqual(report['finding_count'], 1)
        self.assertEqual(report['channels'][0]['channel'], 'ext-example')
        self.assertIn('/another/project/blob/' + 'a'*40, h.load(self.root/'report/details/0.json')[0]['source_url'])

    def test_malformed_rows_do_not_discard_other_channels(self):
        self.envelope['findings'] = [None]
        findings, statuses = self.ingest()
        self.assertEqual(findings, [])
        self.assertEqual(statuses['ext-example']['status'], 'INVALID_EVIDENCE')

    def test_source_credentials_and_path_escapes_are_rejected(self):
        for update in [{'secrets':{'VENDOR_TOKEN':'TOKEN'}}, {'adapter':'../outside.py'}, {'channel':'ruff'}]:
            with self.assertRaises(ValueError):
                e.registry({'scanner_extensions':[{**self.extension, **update}]})

    def test_generated_vendor_jobs_do_not_checkout_source(self):
        from scripts.code_analysis import generate_source_workflow as generator
        import yaml
        shutil.copytree('.github/workflows', self.root/'.github/workflows')
        shutil.copytree('.ci', self.root/'.ci')
        config = h.load(Path('config/code-analysis/service.json'))
        vendor = {**self.extension, 'channel':'ext-vendor', 'name':'Vendor example', 'mode':'vendor',
                  'secrets':{'VENDOR_TOKEN':'VENDOR_ACCESS_TOKEN'}}
        config['scanner_extensions'] = [self.extension, vendor]
        h.write(self.root/'config/code-analysis/service.json', config)
        with patch.object(generator, 'ROOT', self.root):
            jobs = yaml.safe_load(generator.generate())['jobs']
        self.assertNotIn('secrets.', json.dumps(jobs['ext-example']))
        self.assertNotIn('source_repository', json.dumps(jobs['ext-vendor']))
        self.assertIn('secrets.VENDOR_ACCESS_TOKEN', json.dumps(jobs['ext-vendor']))
        self.assertIn('ext-example', jobs['report']['needs'])
        self.assertEqual(jobs['ext-example']['permissions'], {'contents':'read'})

    def test_sensitive_adapter_text_is_withheld(self):
        self.extension['sensitive'] = True
        self.envelope['findings'] = [{'rule_id':'SECRET', 'message':'secret-value', 'severity':'HIGH',
                                     'file':'src/config.py', 'start_line':4}]
        raw, _ = self.ingest()
        self.assertNotIn('secret-value', json.dumps(raw))
        self.assertEqual(raw[0]['rule_concept'], 'hardcoded-secret')

    def test_repository_setup_does_not_reuse_current_repository_identity(self):
        from scripts.code_analysis.configure_instance import configure
        template = h.load(Path('config/code-analysis/service.json'))
        result = configure(template, 'new/source', 'new/observer', 'new/reports', 'develop', {**template['profile'], 'python_root':'src'})
        self.assertEqual(result['source_repository'], 'new/source')
        self.assertEqual(result['preferred_branch'], 'develop')
        self.assertEqual(result['scanner_extensions'], [])
        self.assertEqual(template['source_repository'], 'ARYDESTROYER/Kavach-AgenticSOC')


if __name__ == '__main__':
    unittest.main()
