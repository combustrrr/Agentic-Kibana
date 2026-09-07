"""Behavior tests for exact-revision, current-only public report publication."""
import copy
import io
import json
import tempfile
import unittest
import zipfile
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


if __name__ == '__main__':
    unittest.main()
