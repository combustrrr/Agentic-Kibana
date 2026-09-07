"""Behavior tests for exact-revision, current-only public report publication."""
import copy
import gzip
import io
import json
import tempfile
import unittest
import zipfile
from types import SimpleNamespace
from pathlib import Path
from unittest.mock import patch

from scripts.code_analysis import hosted as h
from scripts.code_analysis import github_service as service


def snapshot():
    return {'schema_version': 'snapshot-v2', 'publishable': False, 'repository_identity': 'owner/repo',
        'commit_sha': 'a' * 40, 'generated_at': '2026-09-07T00:00:00Z', 'workflow_run_ids': ['123'],
        'analysis_channel_count': 2, 'analysis_channels': [
            {'channel': 'ruff', 'name': 'Ruff', 'class': 'code', 'status': 'COMPLETED', 'findings': 1,
             'observation_count': 1, 'observation_ids': ['o1'], 'reason': ''},
            {'channel': 'codeql', 'name': 'CodeQL', 'class': 'security', 'status': 'INVALID_EVIDENCE',
             'findings': None, 'observation_count': 0, 'observation_ids': [], 'reason': 'No output'}],
        'publication_gate': {'policy': 'static-evidence-v1', 'satisfied': False, 'channel_ids': ['ruff', 'codeql']},
        'finding_count': 1, 'observation_count': 1,
        'canonical_findings': [{'stable_id': 'f1', 'severity': 'HIGH', 'file': 'app.py', 'start_line': 2,
            'message': '<script>alert(1)</script>', 'supporting_scanner_families': ['Ruff'], 'observation_ids': ['o1']}],
        'observations': [{'observation_id': 'o1', 'channel': 'ruff', 'scanner_family': 'Ruff', 'rule': 'R1',
                          'file': 'app.py', 'start_line': 2, 'raw_artifact': 'ruff.json'}], 'ai_advisories': []}


class IdentityTests(unittest.TestCase):
    def test_branch_pr_and_fork_identities_do_not_collide(self):
        branch = h.target('owner/repo', 'feature/x', 'a' * 40)
        pr = h.target('owner/repo', 'feature/x', 'a' * 40, pr=42, source_repository='fork/repo', base_sha='b' * 40)
        self.assertNotEqual(branch['id'], pr['id'])
        self.assertEqual(pr['source_repository'], 'fork/repo')

    def test_new_head_keeps_previous_report_but_marks_stale(self):
        old = h.target('owner/repo', 'main', 'a' * 40)
        old.update(report='reports/old', status='current', analysis_key='old', scan_run_id=1)
        new = h.target('owner/repo', 'main', 'b' * 40)
        row = h.reconcile({'targets': [old]}, [new], 'now')['targets'][0]
        self.assertEqual(row['report'], 'reports/old')
        self.assertEqual(row['status'], 'stale')
        self.assertNotIn('scan_run_id', row)

    def test_base_change_invalidates_pr_analysis(self):
        old = h.target('owner/repo', 'work', 'a' * 40, pr=1, base_sha='b' * 40)
        new = {**old, 'base_sha': 'c' * 40}
        self.assertNotEqual(h.analysis_key(old, 'd' * 40, {}), h.analysis_key(new, 'd' * 40, {}))

    def test_source_only_reuse_key_excludes_branch_label(self):
        a = h.target('owner/repo', 'a', 'a' * 40)
        b = h.target('owner/repo', 'b', 'a' * 40)
        self.assertEqual(h.analysis_key(a, 'd' * 40, {}), h.analysis_key(b, 'd' * 40, {}))

    def test_old_completion_cannot_replace_current_head(self):
        old = h.target('owner/repo', 'main', 'a' * 40)
        current = {**old, 'head_sha': 'b' * 40}
        self.assertFalse(h.accept(current, {'target': old, 'analyzed_sha': old['head_sha']}))

    def test_closed_targets_removed_only_from_complete_inventory(self):
        old = h.target('owner/repo', 'main', 'a' * 40)
        self.assertEqual(h.reconcile({'targets': [old]}, [], 'now')['targets'], [])
        with patch.object(service, 'api', side_effect=RuntimeError('failed page')):
            with self.assertRaises(RuntimeError):
                service.discover({'source_repository': 'owner/repo'})

    def test_pagination_is_exhaustive(self):
        with patch.object(service, 'api', side_effect=[[{}] * 100, [{'last': True}]]) as api:
            self.assertEqual(len(service.pages('repos/o/r/branches')), 101)
            self.assertIn('page=2', api.call_args.args[0])

    def test_expired_handoff_requeues_only_when_no_durable_report_exists(self):
        config = {'analysis_repository': 'service/host', 'publishing_repository': 'service/site',
                  'preferred_branch': 'main', 'max_parallel_analyses': 2}
        item = h.target('owner/repo', 'main', 'a' * 40)
        row = {**item, 'analysis_key': h.analysis_key(item, 'd' * 40, config), 'request_id': 'old',
               'scan_run_id': 77, 'tooling_sha': 'd' * 40, 'run_attempt': 1}
        run = {'id': 77, 'run_attempt': 1, 'status': 'completed', 'conclusion': 'success', 'display_title': 'Source analysis old'}
        for durable in (False, True):
            with self.subTest(durable=durable), \
                    patch.object(service, 'release', side_effect=[{'id': 1, 'body': json.dumps({'targets': [row]})},
                        {'body': json.dumps({'targets': [{'collected_run': '77-1'}]})} if durable else None]), \
                    patch.object(service, 'discover', return_value=[item]), \
                    patch.object(service, 'pages', side_effect=[[run], [{'name': 'hosted-report-77-1', 'expired': True}]]), \
                    patch.object(service, 'api', side_effect=[{'default_branch': 'main'}, {'sha': 'd' * 40}, {'workflow_run_id': 78}]) as api, \
                    patch.object(service, 'save_state') as save:
                service.scan(config)
                saved = save.call_args.args[2]['targets'][0]
                self.assertEqual(saved['scan_run_id'], 77 if durable else 78)
                if not durable:
                    self.assertTrue(api.call_args.args[1]['return_run_details'])
                    self.assertEqual(saved['run_attempt'], 1)


class ReportTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.root = Path(self.temp.name)
        self.identity = h.target('owner/repo', 'main', 'a' * 40)

    def tearDown(self):
        self.temp.cleanup()

    def build(self, s=None, **kwargs):
        return h.build(s or snapshot(), self.identity, self.root / 'report', producer_repository='service/host', **kwargs)

    def test_partial_valid_report_preserves_failed_gate(self):
        r = self.build()
        self.assertEqual(r['status'], 'partial')
        self.assertFalse(r['publication_gate']['satisfied'])
        self.assertIsNone(r['channels'][1]['findings'])
        service.validate_bundle(self.root / 'report', r)

    def test_missing_hosted_detail_page_cannot_publish(self):
        report = self.build()
        (self.root / 'report/details/0.json').unlink()
        with self.assertRaisesRegex(ValueError, 'detail pages'):
            service.validate_bundle(self.root / 'report', report)

    def test_complete_policy_findings_are_not_execution_failure(self):
        s = snapshot()
        s['analysis_channels'][1].update(status='POLICY_FINDINGS', findings=0)
        self.assertEqual(self.build(s)['status'], 'current')

    def test_unknown_inapplicability_needs_reason(self):
        s = snapshot()
        s['analysis_channels'][1].update(status='NOT_APPLICABLE', reason='')
        self.assertEqual(self.build(s)['status'], 'partial')

    def test_rejects_mixed_revision(self):
        s = snapshot()
        s['commit_sha'] = 'b' * 40
        with self.assertRaises(ValueError):
            self.build(s)

    def test_rejects_missing_observations(self):
        s = snapshot()
        s['canonical_findings'][0]['observation_ids'] = ['missing']
        with self.assertRaises(ValueError):
            self.build(s)

    def test_rejects_duplicate_canonical_identity(self):
        s = snapshot()
        s['canonical_findings'] *= 2
        s['finding_count'] = 2
        with self.assertRaises(ValueError):
            self.build(s)

    def test_reads_source_without_execution(self):
        (self.root / 'app.py').write_text('first\nraise Exception("must not execute")\nthird')
        self.build(source=self.root)
        d = h.load(self.root / 'report/details/0.json')[0]
        self.assertEqual(d['source_start'], 1)
        self.assertIn('/blob/' + 'a' * 40, d['source_url'])

    def test_secret_findings_do_not_publish_values_or_source(self):
        s = snapshot()
        s['canonical_findings'][0]['message'] = 'secret-value'
        s['observations'][0].update(channel='gitleaks', scanner_family='Gitleaks')
        (self.root / 'app.py').write_text('secret-value')
        self.build(s, source=self.root)
        text = ''.join(p.read_text() for p in (self.root / 'report').rglob('*.json'))
        self.assertNotIn('secret-value', text)
        self.assertFalse((self.root / 'report/source').exists())

    def test_source_traversal_not_read(self):
        s = snapshot()
        s['canonical_findings'][0]['file'] = '../outside'
        self.build(s, source=self.root)
        self.assertIsNone(h.load(self.root / 'report/details/0.json')[0]['source_url'])

    def test_archive_traversal_rejected(self):
        data = io.BytesIO()
        with zipfile.ZipFile(data, 'w') as z:
            z.writestr('../outside', 'payload')
        with self.assertRaises(ValueError):
            service.extract_zip(data.getvalue(), self.root)

    def test_wrong_producer_workflow_rejected_before_download(self):
        row = {**self.identity, 'scan_run_id': 123, 'tooling_sha': 'd' * 40}
        with patch.object(service, 'api', return_value={'path': '.github/workflows/other.yml'}):
            with self.assertRaisesRegex(ValueError, 'producer workflow'):
                service.collect({'analysis_repository': 'service/host'}, row, self.root)

    def test_expired_exact_artifact_is_unavailable(self):
        row = {**self.identity, 'scan_run_id': 123, 'tooling_sha': 'd' * 40, 'run_attempt': 2}
        run = {'path': '.github/workflows/11-source-analysis.yml', 'head_sha': 'd' * 40, 'status': 'completed'}
        with patch.object(service, 'api', return_value=run), patch.object(service, 'pages', return_value=[
                {'name': 'hosted-report-123-1', 'expired': False},
                {'name': 'hosted-report-123-2', 'expired': True}]):
            with self.assertRaisesRegex(ValueError, 'missing or expired'):
                service.collect({'analysis_repository': 'service/host'}, row, self.root)

    def test_changed_head_during_download_keeps_old_files(self):
        current = {**self.identity, 'status': 'partial', 'report': 'reports/old',
                   'asset': 'report-old.json.gz', 'collected_run': '122-1'}
        scan = {**self.identity, 'status': 'collected', 'scan_run_id': 123, 'run_attempt': 1}
        config = {'source_repository': 'owner/repo', 'analysis_repository': 'service/host',
                  'publishing_repository': 'service/site', 'preferred_branch': 'main', 'site_limit_bytes': 1000000}
        old_content = {'report.json': {'analyzed_sha': 'a' * 40, 'source_boundary': 'isolated-tooling-v1'}}
        releases = [{'body': json.dumps({'targets': [scan]})},
                    {'id': 1, 'body': json.dumps({'targets': [current]})}]
        with patch.object(service, 'release', side_effect=releases), patch.object(service, 'discover', side_effect=[
                [self.identity], [{**self.identity, 'head_sha': 'b' * 40}]]), \
                patch.object(service, 'pages', side_effect=[[], [{'name': current['asset'], 'id': 99}]]), \
                patch.object(service, 'collect', return_value={'target': self.identity, 'analyzed_sha': 'a' * 40}), \
                patch.object(service, 'gh', return_value=gzip.compress(json.dumps(old_content).encode())), \
                patch.object(service, 'save_state') as save:
            service.publish(config, self.root)
        self.assertTrue((self.root / 'data/reports/old/report.json.gz').exists())
        self.assertEqual(save.call_args.args[2]['targets'][0]['collected_run'], '122-1')
        self.assertEqual(save.call_args.args[2]['targets'][0]['head_sha'], 'b' * 40)
        self.assertEqual(save.call_args.args[2]['targets'][0]['status'], 'stale')

    def test_snyk_metadata_rejects_executable_requirements(self):
        from scripts.code_analysis.snyk_metadata import requirements, metadata
        path = self.root / 'requirements.txt'
        for unsafe in ['-e .', 'package @ https://example.com/source.tar.gz', '../package']:
            path.write_text(unsafe)
            with self.assertRaises(ValueError):
                requirements(path)
        path.write_text('fastapi==0.110.1\nuvicorn[standard]==0.29.0 # comment')
        self.assertEqual(len(requirements(path)), 2)
        name, text = metadata({'name': 'safe-package', 'version': '1.0', 'requires_dist': ['other>=1']})
        self.assertEqual(name, 'safe_package-1.0.dist-info')
        self.assertIn('Requires-Dist: other>=1', text)
        with self.assertRaises(ValueError):
            metadata({'name': '../bad', 'version': '1.0'})

    def test_scorecard_checks_preserve_unavailable_and_exact_source(self):
        from scripts.code_analysis.scorecard_report import convert
        native = {'repo': {'name': 'github.com/owner/repo', 'commit': 'a' * 40}, 'checks': [
            {'name': 'Branch-Protection', 'score': -1, 'reason': 'Permission unavailable'},
            {'name': 'Pinned-Dependencies', 'score': 4, 'reason': 'Unpinned references'},
            {'name': 'Security-Policy', 'score': 10}]}
        sarif, status = convert(native, 'owner/repo', 'a' * 40)
        self.assertEqual(status['status'], 'CONFIGURED_PARTIAL')
        self.assertEqual(len(sarif['runs'][0]['results']), 1)
        self.assertIn('Branch-Protection', status['reason'])
        with self.assertRaises(ValueError):
            convert(native, 'owner/repo', 'b' * 40)

    def test_javascript_profile_retains_failed_tests_without_credentials(self):
        from scripts.code_analysis import run_profile
        (self.root / 'webui').mkdir()
        with patch('sys.argv', ['profile', 'javascript-test', '--source', str(self.root)]), \
                patch.dict('os.environ', {'GH_TOKEN': 'must-not-inherit', 'VENDOR_SECRET': 'must-not-inherit'}), \
                patch.object(run_profile.subprocess, 'run', return_value=SimpleNamespace(returncode=3)) as run:
            run_profile.main()
        self.assertEqual(h.load(self.root / 'typescript-test-status.json')['test_exit_code'], 3)
        self.assertNotIn('GH_TOKEN', run.call_args.kwargs['env'])
        self.assertNotIn('VENDOR_SECRET', run.call_args.kwargs['env'])

    def test_api_profile_timeout_stops_source_process_and_records_failure(self):
        from scripts.code_analysis import run_profile
        (self.root / 'backend').mkdir()
        with patch('sys.argv', ['profile', 'api-fuzz', '--source', str(self.root)]), \
                patch.object(run_profile.subprocess, 'Popen') as process, \
                patch.object(run_profile.urllib.request, 'urlopen', return_value=io.BytesIO(b'{}')), \
                patch.object(run_profile.subprocess, 'run', side_effect=run_profile.subprocess.TimeoutExpired('fuzzer', 300)):
            with self.assertRaises(run_profile.subprocess.TimeoutExpired):
                run_profile.main()
        process.return_value.terminate.assert_called_once()
        self.assertEqual(h.load(self.root / 'schemathesis-status.json')['status'], 'OPERATIONAL_FAILURE')

    def test_closed_pr_retains_exact_head_review_evidence(self):
        from scripts.code_analysis import collect_coderabbit as rabbit
        pr = {'state': 'closed', 'number': 110, 'head': {'sha': 'a' * 40, 'ref': 'feature', 'repo': {'full_name': 'fork/repo'}}}
        review = {'user': {'login': 'coderabbitai[bot]'}, 'commit_id': 'a' * 40}
        with patch.object(rabbit, 'request_json', return_value=pr), patch.object(rabbit, 'paged', side_effect=[[review], []]):
            evidence, status = rabbit.collect('owner/repo', 'feature', 'a' * 40, 'token', pr_number=110)
        self.assertEqual(status['status'], 'COMPLETED_OPTIONAL')
        self.assertEqual(evidence['pull_requests'], [110])


if __name__ == '__main__':
    unittest.main()
