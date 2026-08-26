import json, tempfile, unittest
from datetime import datetime, timezone
from pathlib import Path
from scripts.code_analysis.channel_status import build as build_channel_status
from scripts.code_analysis.dashboard import generate, github_summary, validate_snapshot, write_dashboard
from scripts.code_analysis.monitoring import EvidenceError, build_snapshot, canonicalize, check_key, compare, defectdojo_fixture, effective_triage, stable_id
from scripts.code_analysis.normalizer import TscParser, XenonParser
from scripts.code_analysis.provenance import build as build_provenance
from scripts.code_analysis.publish_snapshot import publish

MANIFEST={"schema_version":"1","required_static_channels":[
    {"channel":"codeql","scanner_family":"CodeQL","surface":"semantic","artifact_patterns":["*codeql*.sarif"]},
    {"channel":"semgrep","scanner_family":"Semgrep","surface":"pattern","artifact_patterns":["*semgrep*.json"]}]}
RUN={"commit_sha":"abc","branch":"feature","workflow_run_id":"1","generated_at":"2026-08-25T00:00:00Z"}
def raw(tool="CodeQL",line=10,rule="python/sql-injection",snippet="db.execute(query)"):
    return {"id":f"{tool}-{line}","source_tool":tool,"file":"backend/app/a.py","start_line":line,"end_line":line,"rule_id":rule,"rule_concept":"sql-injection","severity":"HIGH","category":"SECURITY","code_snippet":snippet,"message":"unsafe query"}
def evidence(items): return canonicalize(items,"combustrrr/Agentic-Kibana",RUN,MANIFEST)
def status(codeql="COMPLETED",semgrep="COMPLETED"):
    return {"schema_version":"1","channels":[{"scanner_family":"CodeQL","status":codeql},{"scanner_family":"Semgrep","status":semgrep}],"analysis_change_flags":[]}
def snapshot(items=None, channel_state=None):
    current=evidence(items or [raw()]);channels=channel_state or status()
    provenance={"commit_sha":"abc","workflow_run_ids":["1","2"],"artifact_hashes":[{"path":"codeql.sarif","sha256":"a"*64}]}
    return build_snapshot(current,channels,provenance)

class MonitoringTests(unittest.TestCase):
    def test_identity_is_canonical_and_missing_symbol_explicit(self):
        a=raw();b={**a,"file":"backend\\app\\a.py"}
        self.assertEqual(stable_id("repo",a),stable_id("repo",b));self.assertIn("sid-v1:",stable_id("repo",a))
    def test_duplicate_evidence_is_one_finding_with_two_families(self):
        doc=evidence([raw("CodeQL"),raw("Semgrep")]);self.assertEqual(len(doc["findings"]),1)
        self.assertEqual(doc["findings"][0]["observation_count"],2);self.assertEqual(doc["findings"][0]["scanner_family_count"],2)
    def test_exact_new_and_conservation(self):
        base=evidence([raw(line=10)]);base["baseline_id"]="base";current=evidence([raw(line=10),raw(line=30,snippet="other")])
        result=compare(current,base,None,status(),{"decisions":[]});self.assertEqual(result["counts"],{"EXISTING":1,"NEW":1})
    def test_missing_owner_is_indeterminate_not_lost(self):
        base=evidence([raw("CodeQL"),raw("Semgrep")]);base["baseline_id"]="base";current=evidence([])
        result=compare(current,base,None,status(semgrep="FAILED"),{"decisions":[]});self.assertEqual(result["counts"],{"INDETERMINATE":1})
    def test_not_observed_when_all_owners_complete(self):
        base=evidence([raw()]);base["baseline_id"]="base";result=compare(evidence([]),base,None,status(),{"decisions":[]})
        self.assertEqual(result["counts"],{"NOT_OBSERVED":1})
    def test_triage_expiry_and_no_identity_transfer(self):
        old=evidence([raw()]);sid=old["findings"][0]["stable_id"]
        registry={"decisions":[{"stable_id":sid,"status":"FALSE_POSITIVE","expires_at":"2020-01-01T00:00:00Z"}]}
        self.assertEqual(effective_triage(registry,datetime.now(timezone.utc))[sid]["effective_status"],"UNREVIEWED")
        changed=evidence([raw(snippet="different statement")]);self.assertNotEqual(sid,changed["findings"][0]["stable_id"])
    def test_defectdojo_identity_ignores_line_after_internal_move(self):
        finding=evidence([raw()])["findings"][0];moved={**finding,"start_line":150};other={**finding,"stable_id":"sid-v1:other"}
        exports=defectdojo_fixture([finding,moved,other])["findings"]
        self.assertEqual(exports[0]["unique_id_from_tool"],exports[1]["unique_id_from_tool"]);self.assertNotEqual(exports[0]["unique_id_from_tool"],exports[2]["unique_id_from_tool"])
    def test_required_channel_missing_fails(self):
        with tempfile.TemporaryDirectory() as d:
            root=Path(d);(root/"codeql.sarif").write_text("{}")
            built=build_channel_status(MANIFEST,root);self.assertEqual([x["status"] for x in built["channels"]],["COMPLETED","NOT_CONFIGURED"])
    def test_dashboard_is_bounded_and_exposes_all_current_findings(self):
        result=snapshot([raw("CodeQL"),raw("Semgrep")])
        with tempfile.TemporaryDirectory() as d:
            output=Path(d)/"index.html";generate(result,output);page=output.read_text()
            self.assertIn("All canonical findings",page);self.assertIn("slice((page-1)*size,page*size)",page)
            self.assertIn("Raw observations",page);self.assertIn("Current Code Quality",github_summary(result))
    def test_invalid_current_fails_closed(self):
        base=evidence([]);base["baseline_id"]="base";bad=evidence([]);bad["schema_version"]="future"
        with self.assertRaises(EvidenceError): compare(bad,base,None,status(),{"decisions":[]})
    def test_check_key_is_restart_stable_and_commit_scoped(self):
        self.assertEqual(check_key("repo","a"),check_key("repo","a"));self.assertNotEqual(check_key("repo","a"),check_key("repo","b"))
    def test_unreviewed_identity_migration_fails(self):
        with self.assertRaises(EvidenceError): effective_triage({"decisions":[],"identity_migrations":[{"from_stable_id":"a","to_stable_id":"b"}]})
    def test_workflow_has_only_minimum_write_permission(self):
        text=Path(".github/workflows/05-issue-aggregation.yml").read_text(encoding="utf-8")
        permissions=text.split("permissions:",1)[1].split("jobs:",1)[0]
        self.assertIn("checks: write",permissions);self.assertIn("contents: read",permissions);self.assertIn("actions: read",permissions)
        self.assertNotIn("issues: write",text);self.assertNotIn("pull-requests: write",text);self.assertNotIn("contents: write",text)

    def test_snapshot_reconciles_findings_and_observations(self):
        result=snapshot([raw("CodeQL"),raw("Semgrep")])
        self.assertTrue(result["publishable"]);self.assertEqual(result["finding_count"],1)
        self.assertEqual(result["observation_count"],2);validate_snapshot(result)

    def test_snapshot_rejects_incomplete_channels_and_mixed_commit(self):
        with self.assertRaises(EvidenceError): snapshot(channel_state=status(semgrep="FAILED"))
        current=evidence([raw()]);provenance={"commit_sha":"other","workflow_run_ids":["1"],"artifact_hashes":[{"path":"a","sha256":"a"*64}]}
        with self.assertRaises(EvidenceError): build_snapshot(current,status(),provenance)

    def test_provenance_hashes_and_publication_roll_back(self):
        with tempfile.TemporaryDirectory() as d:
            root=Path(d);artifacts=root/"artifacts";artifacts.mkdir();(artifacts/"a.json").write_text("one")
            provenance=build_provenance(artifacts,"abc",["1"]);self.assertEqual(len(provenance["artifact_hashes"][0]["sha256"]),64)
            first=root/"first";write_dashboard(snapshot(),first);published=root/"published";publish(first,published)
            self.assertTrue((published/"current"/"index.html").is_file())
            bad=root/"bad";bad.mkdir();(bad/"current-snapshot.json").write_text("{}")
            with self.assertRaises(ValueError): publish(bad,published)
            self.assertTrue((published/"current"/"index.html").is_file())

    def test_tsc_and_xenon_are_structured(self):
        with tempfile.TemporaryDirectory() as d:
            root=Path(d);tsc=root/"tsc-results.txt";tsc.write_text("src/a.ts(4,9): error TS2322: Type 'string' is not assignable")
            xenon=root/"xenon-results.txt";xenon.write_text('ERROR:xenon:block "backend/app/a.py:12 function" has a rank of F')
            self.assertEqual(TscParser().parse(tsc)[0].rule_id,"TS2322")
            self.assertEqual(XenonParser().parse(xenon)[0].source_tool,"Xenon")

    def test_original_proposal_tools_are_explicitly_accounted_for(self):
        catalog=json.loads(Path("config/code-analysis/proposal-tool-catalog.json").read_text(encoding="utf-8"))
        tools={row["tool"]:row for row in catalog["tools"]}
        selected={"CodeRabbit","CodeQL","Semgrep","Bandit","Ruff","Pyright","ESLint","TypeScript","OSV-Scanner","Snyk","Gitleaks","Trivy","CodeScene","Schemathesis","Atheris"}
        self.assertTrue(selected.issubset(tools))
        required=json.loads(Path("config/code-analysis/required-channels.json").read_text(encoding="utf-8"))
        channels={row["channel"] for row in required["required_static_channels"]}
        for row in tools.values():
            if row["state"] == "ACTIVE_REQUIRED": self.assertIn(row["channel"],channels)

if __name__=="__main__": unittest.main()
