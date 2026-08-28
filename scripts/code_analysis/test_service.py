import json, os, tempfile, unittest, urllib.request, zipfile
from argparse import Namespace
from datetime import datetime, timezone
from pathlib import Path
from unittest.mock import patch
from click.testing import CliRunner
from scripts.code_analysis.audit_workflows import audit as audit_workflows
from scripts.code_analysis.bound_sarif import bound as bound_sarif
from scripts.code_analysis.channel_status import build as build_channel_status
from scripts.code_analysis.collect_coderabbit import collect as collect_coderabbit
from scripts.code_analysis.dashboard import generate, github_summary, validate_snapshot, write_dashboard
from scripts.code_analysis.evidence_contract import build as build_evidence_contract
from scripts.code_analysis.monitoring import EvidenceError, build_snapshot, canonicalize, check_key, compare, defectdojo_fixture, effective_triage, stable_id
from scripts.code_analysis.normalizer import CodeRabbitParser, CoverageParser, RadonParser, SchemathesisParser, TscParser, XenonParser, main as normalize_cli
from scripts.code_analysis.pipeline import build as build_pipeline
from scripts.code_analysis.provenance import build as build_provenance
from scripts.code_analysis.publish_snapshot import publish
from scripts.code_analysis.pull_worker import (_CredentialIsolatingRedirectHandler,
    artifact_branch_key, artifact_commit, read_state, read_token, safe_extract,
    select_artifact, select_artifact_by_id)
from scripts.code_analysis.validate_sbom import _denied_license, evaluate as evaluate_sbom
from scripts.code_analysis.snapshot import build_additional_channels

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
    def test_distinct_same_line_sinks_are_never_collapsed(self):
        left={**raw("CodeQL"),"id":"left","start_col":4}
        right={**raw("CodeQL"),"id":"right","start_col":30}
        doc=evidence([left,right])
        self.assertEqual(len(doc["findings"]),2)
        self.assertEqual(len(doc["observations"]),2)
    def test_missing_region_evidence_has_unique_conservative_identities(self):
        left={**raw("CodeQL",snippet=""),"id":"native-left","native_result_id":"native-left"}
        right={**raw("CodeQL",snippet=""),"id":"native-right","native_result_id":"native-right"}
        doc=evidence([left,right])
        self.assertEqual(len(doc["findings"]),2)
        self.assertEqual(len({row["stable_id"] for row in doc["findings"]}),2)
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
            contract=build_evidence_contract(MANIFEST,root,"repo/fork","abc",["1"])
            built=build_channel_status(MANIFEST,root,contract=contract,repository="repo/fork",commit="abc")
            self.assertEqual([x["status"] for x in built["channels"]],["COMPLETED","INVALID_EVIDENCE"])

    def test_channel_contract_rejects_mixed_commit_and_tampering(self):
        with tempfile.TemporaryDirectory() as d:
            root=Path(d);(root/"codeql.sarif").write_text("{}")
            contract=build_evidence_contract(MANIFEST,root,"repo/fork","abc",["1"])
            with self.assertRaisesRegex(ValueError,"commit"):
                build_channel_status(MANIFEST,root,contract=contract,
                                     repository="repo/fork",commit="different")
            (root/"codeql.sarif").write_text('{"changed":true}')
            built=build_channel_status(MANIFEST,root,contract=contract,
                                       repository="repo/fork",commit="abc")
            self.assertEqual(built["channels"][0]["status"],"INVALID_EVIDENCE")

    def test_nested_scanner_outputs_are_valid_retained_evidence(self):
        manifest={"schema_version":"1","required_static_channels":[
            {"channel":"codeql","scanner_family":"CodeQL","surface":"semantic",
             "artifact_patterns":["*codeql*/*.sarif"]},
            {"channel":"checkov","scanner_family":"Checkov","surface":"iac",
             "artifact_patterns":["*checkov*/*.sarif"]}]}
        with tempfile.TemporaryDirectory() as d:
            root=Path(d)
            (root/"codeql-python-sarif").mkdir()
            (root/"codeql-python-sarif"/"python.sarif").write_text("{}")
            (root/"checkov-results").mkdir()
            (root/"checkov-results"/"results_sarif.sarif").write_text("{}")
            contract=build_evidence_contract(manifest,root,"repo/fork","abc",["1"])
            built=build_channel_status(manifest,root,contract=contract,
                                       repository="repo/fork",commit="abc")
            self.assertTrue(all(row["status"] == "COMPLETED" for row in built["channels"]))

    def test_github_sarif_bound_is_deterministic_and_severity_first(self):
        document={"runs":[{"results":[
            {"ruleId":"low","level":"note","message":{"text":"low"}},
            {"ruleId":"high-b","level":"error","message":{"text":"b"}},
            {"ruleId":"high-a","level":"error","message":{"text":"a"}},
        ]}]}
        result=bound_sarif(document,2)
        self.assertEqual([row["ruleId"] for row in result["runs"][0]["results"]],
                         ["high-a","high-b"])

    def test_sbom_policy_accepts_standard_inventories_and_reports_denied_licenses(self):
        cyclonedx={"bomFormat":"CycloneDX","components":[
            {"name":"safe","licenses":[{"license":{"id":"MIT"}}]},
            {"name":"review","licenses":[{"license":{"id":"AGPL-3.0-only"}}]},
        ]}
        spdx={"spdxVersion":"SPDX-2.3","packages":[
            {"name":"safe-spdx","licenseDeclared":"Apache-2.0","licenseConcluded":"NOASSERTION"}
        ]}
        with tempfile.TemporaryDirectory() as d:
            root=Path(d);cdx=root/"image.cdx.json";spdx_path=root/"image.spdx.json"
            cdx.write_text(json.dumps(cyclonedx));spdx_path.write_text(json.dumps(spdx))
            sbom_status,sarif=evaluate_sbom([cdx,spdx_path])
        self.assertEqual(sbom_status["status"],"POLICY_FINDINGS")
        self.assertEqual(sbom_status["finding_count"],1)
        self.assertEqual(sbom_status["formats"],["CycloneDX","SPDX"])
        self.assertEqual(sarif["runs"][0]["tool"]["driver"]["name"],"SBOM Policy")
        self.assertEqual(len(sarif["runs"][0]["results"]),1)

    def test_sbom_policy_matches_complete_spdx_identifiers_not_lgpl_substrings(self):
        self.assertFalse(_denied_license("LGPL-2.0-only"))
        self.assertFalse(_denied_license("LGPL-2.1-or-later"))
        self.assertTrue(_denied_license("MIT OR GPL-2.0-only"))
        self.assertTrue(_denied_license("AGPL-3.0-or-later"))

    def test_dashboard_is_bounded_and_exposes_all_current_findings(self):
        result=snapshot([raw("CodeQL"),raw("Semgrep")])
        with tempfile.TemporaryDirectory() as d:
            output=Path(d)/"index.html";generate(result,output);page=output.read_text()
            self.assertIn("All canonical findings",page);self.assertIn("slice((page-1)*size,page*size)",page)
            self.assertIn("searchIndex.get(x.stable_id)",page)
            self.assertIn("Raw evidence records",page);self.assertIn("Current Code Quality",github_summary(result))
            self.assertIn("Snapshot integrity and source proof",page)
            self.assertIn("artifactHashes",page)
            self.assertIn("Security focus",page)
            self.assertIn("Security findings",page)
            self.assertIn("securityFinding",page)
            self.assertIn("Contextual AI candidates",page)
            self.assertIn("Supervisor overview",page)
            self.assertIn("Highest-risk areas",page)
            self.assertIn("Publication path",page)
            self.assertIn("data-filter",page)
            self.assertIn("copyLink",page)
    def test_required_manifest_maps_sixteen_channels_to_four_workflows(self):
        root=Path(__file__).resolve().parents[2]
        manifest=json.loads((root/"config/code-analysis/required-channels.json").read_text(encoding="utf-8"))
        channels=manifest["required_static_channels"]
        self.assertEqual(len(channels),16)
        self.assertEqual({row["workflow"] for row in channels},{"01-code-quality.yml","02-security-sast.yml","03-dependency-security.yml","04-code-health.yml"})
        self.assertTrue(all(row["artifact_patterns"] for row in channels))

    def test_real_manifest_accepts_one_retained_artifact_for_all_sixteen_channels(self):
        manifest=json.loads(Path("config/code-analysis/required-channels.json").read_text(
            encoding="utf-8"))
        artifact_names={
            "ruff":"ruff-results.json", "pyright":"pyright-results.json",
            "eslint":"eslint-results.json", "typescript":"tsc-results.txt",
            "bandit":"bandit-results.json", "codeql":"codeql-python.sarif",
            "semgrep":"semgrep-results.json", "osv":"osv-results.sarif",
            "gitleaks":"gitleaks-results.sarif", "trivy":"trivy-fs.sarif",
            "checkov":"checkov-results.sarif", "hadolint":"hadolint.sarif",
            "vulture":"vulture-results.txt", "radon":"radon-cc.json",
            "xenon":"xenon-results.txt", "coverage":"coverage.json",
        }
        with tempfile.TemporaryDirectory() as d:
            root=Path(d)
            for channel,name in artifact_names.items():
                folder=root/channel
                folder.mkdir()
                (folder/name).write_text("{}",encoding="utf-8")
            contract=build_evidence_contract(manifest,root,"repo/fork","abc",["1","2","3","4"])
            built=build_channel_status(manifest,root,contract=contract,
                                       repository="repo/fork",commit="abc")
            self.assertEqual(len(built["channels"]),16)
            self.assertTrue(all(row["status"] == "COMPLETED" for row in built["channels"]))
    def test_enterprise_workflow_policy_and_advisory_check_contract(self):
        self.assertEqual(audit_workflows(),[])
        layout=json.loads((Path(__file__).resolve().parents[2]/"config/code-analysis/service-layout.json").read_text(encoding="utf-8"))
        self.assertEqual(layout["boundary"],"read-only-external")
        self.assertIn("domain",layout["layers"])
        self.assertIn("presentation",layout["layers"])
        self.assertIn("infrastructure_adapters",layout["layers"])
        aggregation=(Path(__file__).resolve().parents[2]/".github/workflows/05-issue-aggregation.yml").read_text(encoding="utf-8")
        self.assertIn('conclusion="neutral"',aggregation)
        self.assertIn("if-no-files-found: error",aggregation)
        self.assertIn("Bounded pipeline diagnostic",aggregation)
        self.assertIn("tail -n 30 pipeline-diagnostic.log",aggregation)
        self.assertIn("REDACTED",aggregation)
        coderabbit=(Path(__file__).resolve().parents[2]/".coderabbit.yaml").read_text(encoding="utf-8")
        self.assertIn('base_branches:\n      - ".*"',coderabbit)
        self.assertIn("timeout_ms: 900000",coderabbit)

    def test_analysis_workflows_use_no_deprecated_node20_action_pins(self):
        deprecated={
            "11d5960a326750d5838078e36cf38b85af677262",
            "a26af69be951a213d495a4c3e4e4022e16d87065",
            "49933ea5288caeca8642d1e84afbd3f7d6820020",
            "6d786de4d6f3531a740e445b53a42b622bbbace8",
        }
        for number in range(1,10):
            for path in Path(".github/workflows").glob(f"0{number}-*.yml"):
                text=path.read_text(encoding="utf-8")
                for sha in deprecated:
                    self.assertNotIn(sha,text,path.name)
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

    def test_qa_vm_profile_is_loopback_read_only_and_credential_scoped(self):
        compose=Path("deploy/code-analysis-dashboard/compose.yml").read_text(encoding="utf-8")
        unit=Path("deploy/code-analysis-dashboard/agentic-findings-pull.service").read_text(encoding="utf-8")
        self.assertIn('127.0.0.1:8787:8080',compose);self.assertIn("read_only: true",compose)
        self.assertIn("cap_drop:\n      - ALL",compose);self.assertIn("/healthz",compose)
        nginx=Path("deploy/code-analysis-dashboard/nginx.conf").read_text(encoding="utf-8")
        timer=Path("deploy/code-analysis-dashboard/agentic-findings-pull.timer").read_text(encoding="utf-8")
        self.assertIn("if (!-f /srv/current/index.html) { return 503; }",nginx)
        self.assertIn("OnUnitInactiveSec=5min",timer)
        self.assertIn("LoadCredential=github-token:",unit);self.assertIn("NoNewPrivileges=true",unit)
        self.assertNotIn("GH_TOKEN=",unit);self.assertNotIn("github-token",unit.split("ExecStart=",1)[1].splitlines()[0])

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
            with self.assertRaisesRegex(ValueError,"repository"):
                publish(first,published,"wrong/repository","abc")
            with self.assertRaisesRegex(ValueError,"branch"):
                publish(first,published,"combustrrr/Agentic-Kibana","abc","wrong-branch")
            self.assertTrue((published/"current"/"index.html").is_file())

    def test_tsc_and_xenon_are_structured(self):
        with tempfile.TemporaryDirectory() as d:
            root=Path(d);tsc=root/"tsc-results.txt";tsc.write_text("src/a.ts(4,9): error TS2322: Type 'string' is not assignable")
            xenon=root/"xenon-results.txt";xenon.write_text('ERROR:xenon:block "backend/app/a.py:12 function" has a rank of F')
            self.assertEqual(TscParser().parse(tsc)[0].rule_id,"TS2322")
            self.assertEqual(XenonParser().parse(xenon)[0].source_tool,"Xenon")

    def test_radon_and_coverage_are_visible_structured_findings(self):
        with tempfile.TemporaryDirectory() as d:
            root=Path(d);radon=root/"radon-cc.json";coverage=root/"coverage.json"
            radon.write_text(json.dumps({"backend/app/a.py":[{"type":"F","name":"hard",
                "lineno":12,"endline":40,"complexity":18,"rank":"C","closures":[]}]}),encoding="utf-8")
            coverage.write_text(json.dumps({"files":{"backend/app/a.py":{"missing_lines":[4,8,9],
                "summary":{"percent_covered":42.5}}}}),encoding="utf-8")
            radon_findings=RadonParser().parse(radon);coverage_findings=CoverageParser().parse(coverage)
            self.assertEqual(radon_findings[0].source_tool,"Radon")
            self.assertEqual(radon_findings[0].category,"COMPLEXITY")
            self.assertEqual(coverage_findings[0].source_tool,"Coverage.py")
            self.assertIn("3 executable lines",coverage_findings[0].message)

    def test_schemathesis_junit_failures_are_structured_dynamic_findings(self):
        with tempfile.TemporaryDirectory() as d:
            report=Path(d)/"fuzzing-results.xml"
            report.write_text('<testsuite><testcase name="GET /cases"><failure message="Status code: 500">Internal Server Error</failure></testcase></testsuite>',encoding="utf-8")
            findings=SchemathesisParser().parse(report)
            self.assertEqual(len(findings),1)
            self.assertEqual(findings[0].source_tool,"Schemathesis")
            self.assertEqual(findings[0].rule_concept,"api-500-crash")
            self.assertEqual(findings[0].category,"DYNAMIC")

    def test_malformed_scanner_artifact_fails_normalization(self):
        with tempfile.TemporaryDirectory() as d:
            root=Path(d);artifacts=root/"artifacts";artifacts.mkdir()
            (artifacts/"radon-cc.json").write_text("{broken",encoding="utf-8")
            result=CliRunner().invoke(normalize_cli,["--input-dir",str(artifacts),
                                                     "--output-dir",str(root/"out")])
            self.assertNotEqual(result.exit_code,0)
            self.assertIn("rejected malformed scanner artifacts",result.output)

    def test_monitored_commits_trigger_scanners_then_one_aggregator(self):
        monitored='branches: ["**"]'
        for name in ("01-code-quality.yml","02-security-sast.yml",
                     "03-dependency-security.yml","04-code-health.yml"):
            workflow=Path(".github/workflows",name).read_text(encoding="utf-8")
            self.assertIn(monitored,workflow)
        aggregator=Path(".github/workflows/05-issue-aggregation.yml").read_text(encoding="utf-8")
        self.assertIn('workflows: ["Code Health & Technical Debt"]',aggregator)
        self.assertIn("github.event.workflow_run.event == 'push'",aggregator)
        self.assertNotIn("\n  push:\n",aggregator)
        dependency=Path(".github/workflows/03-dependency-security.yml").read_text(encoding="utf-8")
        self.assertIn("path: gitleaks-results.sarif",dependency)
        self.assertIn("CONFIGURED_PARTIAL", dependency)
        self.assertIn("potential projects failed|Missing required packages", dependency)
        self.assertIn('[[ "$scan_exit" -le 1 ]]', dependency)

    def test_manual_cross_branch_jobs_never_execute_target_only_analysis_tooling(self):
        quality=Path(".github/workflows/01-code-quality.yml").read_text(encoding="utf-8")
        self.assertIn("python .analysis-tooling/scripts/code_analysis/audit_workflows.py",
                      quality)
        self.assertNotIn("run: python scripts/code_analysis/audit_workflows.py", quality)
        self.assertGreaterEqual(quality.count("scripts/code_analysis"), 2)
        for trusted_policy_input in (".coderabbit.yaml", ".github/workflows",
                                     "config/code-analysis", "deploy"):
            self.assertIn(trusted_policy_input, quality)

        for workflow_name in ("01-code-quality.yml", "02-security-sast.yml",
                              "03-dependency-security.yml", "04-code-health.yml"):
            workflow=Path(".github/workflows",workflow_name).read_text(encoding="utf-8")
            self.assertIn("inputs.scan_sha || github.event.pull_request.head.sha || github.sha",
                          workflow)

    def test_original_proposal_tools_are_explicitly_accounted_for(self):
        catalog=json.loads(Path("config/code-analysis/proposal-tool-catalog.json").read_text(encoding="utf-8"))
        tools={row["tool"]:row for row in catalog["tools"]}
        selected={"CodeRabbit","CodeQL","Semgrep","Bandit","Ruff","Pyright","ESLint","TypeScript","OSV-Scanner","Snyk","Gitleaks","Trivy","CodeScene","Schemathesis","Atheris"}
        self.assertTrue(selected.issubset(tools))
        required=json.loads(Path("config/code-analysis/required-channels.json").read_text(encoding="utf-8"))
        channels={row["channel"] for row in required["required_static_channels"]}
        for row in tools.values():
            if row["state"] == "ACTIVE_REQUIRED": self.assertIn(row["channel"],channels)

    def test_shared_pipeline_builds_and_atomically_publishes(self):
        with tempfile.TemporaryDirectory() as d:
            root=Path(d);artifacts=root/"artifacts";artifacts.mkdir()
            (artifacts/"codeql.sarif").write_text(json.dumps({"version":"2.1.0","runs":[]}),encoding="utf-8")
            (artifacts/"semgrep.json").write_text('{"results":[]}',encoding="utf-8")
            (artifacts/"snyk-status.json").write_text(json.dumps({
                "schema_version":"1","scanner_family":"Snyk",
                "status":"CONFIGURED_COMPLETE","surfaces":{"sca":"success","code":"success"}
            }),encoding="utf-8")
            manifest=root/"manifest.json";manifest.write_text(json.dumps(MANIFEST),encoding="utf-8")
            output=root/"run";publication=root/"published"
            build_pipeline(Namespace(artifacts=artifacts,output=output,repository="repo/fork",commit="abc",
                                     branch="feature",workflow_run_id=["1"],manifest=manifest,
                                     publication_root=publication))
            self.assertTrue((output/"normalized"/"current-snapshot.json").is_file())
            self.assertTrue((publication/"current"/"index.html").is_file())
            current=json.loads((output/"normalized"/"current-snapshot.json").read_text(encoding="utf-8"))
            additional={row["tool"]:row for row in current["additional_channels"]}
            self.assertEqual(additional["Snyk"]["status"],"CONFIGURED_COMPLETE")
            self.assertEqual(additional["CodeRabbit"]["status"],"PENDING_REVIEW")
            self.assertEqual(additional["CodeRabbit"]["evidence_source"],"AI_ADVISORY")
            dashboard=(publication/"current"/"index.html").read_text(encoding="utf-8")
            self.assertIn("Security controls &amp; optional assurance",dashboard)
            self.assertIn("Operational assurance",dashboard)
            self.assertIn("Required scanner evidence",dashboard)
            self.assertIn("Critical and high review queue",dashboard)
            self.assertIn("Scanner distribution",dashboard)

    def test_real_sixteen_channel_pipeline_builds_complete_dashboard(self):
        sarif=json.dumps({"version":"2.1.0","runs":[]})
        files={
            "quality/ruff-results.json":"[]",
            "quality/pyright-results.json":json.dumps({"generalDiagnostics":[]}),
            "quality/eslint-results.json":"[]",
            "quality/tsc-results.txt":"",
            "quality/bandit-results.json":json.dumps({"results":[]}),
            "sast/codeql-python.sarif":sarif,
            "sast/semgrep-results.json":json.dumps({"results":[]}),
            "supply/osv-results.sarif":sarif,
            "supply/gitleaks-results.sarif":sarif,
            "supply/trivy-fs.sarif":sarif,
            "supply/checkov-results.sarif":sarif,
            "supply/hadolint.sarif":sarif,
            "health/vulture-results.txt":"",
            "health/radon-cc.json":"{}",
            "health/xenon-results.txt":"",
            "health/coverage.json":json.dumps({"files":{}}),
            "optional/snyk-status.json":json.dumps({
                "schema_version":"1","scanner_family":"Snyk",
                "status":"NOT_CONFIGURED","reason":"test fixture",
            }),
        }
        with tempfile.TemporaryDirectory() as d:
            root=Path(d);artifacts=root/"artifacts"
            for relative,content in files.items():
                target=artifacts/relative
                target.parent.mkdir(parents=True,exist_ok=True)
                target.write_text(content,encoding="utf-8")
            output=root/"output";publication=root/"published"
            build_pipeline(Namespace(
                artifacts=artifacts,output=output,
                repository="combustrrr/Agentic-Kibana",commit="a"*40,
                branch="Testing",workflow_run_id=["1","2","3","4"],
                manifest=Path("config/code-analysis/required-channels.json"),
                tool_catalog=Path("config/code-analysis/proposal-tool-catalog.json"),
                publication_root=publication,
            ))
            channel_status=json.loads((output/"channel-status.json").read_text(encoding="utf-8"))
            snapshot=json.loads((output/"normalized/current-snapshot.json").read_text(encoding="utf-8"))
            self.assertEqual(len(channel_status["channels"]),16)
            self.assertTrue(all(row["status"] == "COMPLETED"
                                for row in channel_status["channels"]))
            self.assertTrue(snapshot["publishable"])
            self.assertEqual(snapshot["finding_count"],0)
            self.assertTrue((publication/"current/index.html").is_file())

    def test_pull_worker_rejects_zip_path_traversal(self):
        with tempfile.TemporaryDirectory() as d:
            root=Path(d);archive=root/"bad.zip";destination=root/"out";destination.mkdir()
            with zipfile.ZipFile(archive,"w") as bundle: bundle.writestr("../escape.txt","bad")
            with self.assertRaises(ValueError): safe_extract(archive,destination)

    def test_pull_worker_rejects_symlink_and_archive_limit(self):
        with tempfile.TemporaryDirectory() as d:
            root=Path(d);destination=root/"out";destination.mkdir()
            symlink=root/"link.zip"
            with zipfile.ZipFile(symlink,"w") as bundle:
                entry=zipfile.ZipInfo("dashboard/link");entry.create_system=3
                entry.external_attr=(0o120777 << 16);bundle.writestr(entry,"target")
            with self.assertRaisesRegex(ValueError,"symlink"): safe_extract(symlink,destination)
            with patch("scripts.code_analysis.pull_worker.MAX_ARCHIVE_FILES",0):
                with self.assertRaisesRegex(ValueError,"too many files"):
                    safe_extract(symlink,destination)

    def test_pull_worker_extracts_only_the_served_dashboard_tree(self):
        with tempfile.TemporaryDirectory() as d:
            root=Path(d);archive=root/"artifact.zip";destination=root/"out";destination.mkdir()
            with zipfile.ZipFile(archive,"w") as bundle:
                bundle.writestr("dashboard/index.html","dashboard")
                bundle.writestr("normalized/large.json","not served")
            safe_extract(archive,destination,include_prefix="dashboard")
            self.assertEqual((destination/"dashboard/index.html").read_text(),"dashboard")
            self.assertFalse((destination/"normalized").exists())

    def test_pull_worker_reads_protected_token_file(self):
        with tempfile.TemporaryDirectory() as d:
            token_file=Path(d)/"github-token";token_file.write_text("read-only-token\n",encoding="utf-8")
            previous_token=os.environ.pop("GH_TOKEN",None);previous_file=os.environ.get("GH_TOKEN_FILE")
            try:
                os.environ["GH_TOKEN_FILE"]=str(token_file)
                self.assertEqual(read_token(),"read-only-token")
            finally:
                if previous_token is not None: os.environ["GH_TOKEN"]=previous_token
                if previous_file is None: os.environ.pop("GH_TOKEN_FILE",None)
                else: os.environ["GH_TOKEN_FILE"]=previous_file

    def test_pull_worker_never_forwards_github_auth_to_artifact_storage(self):
        handler=_CredentialIsolatingRedirectHandler()
        request=urllib.request.Request(
            "https://api.github.com/repos/org/repo/actions/artifacts/1/zip",
            headers={"Authorization":"Bearer secret-token"},
        )
        storage=handler.redirect_request(
            request,None,302,"Found",{},"https://artifact.example/signed/archive.zip"
        )
        self.assertIsNotNone(storage)
        self.assertIsNone(storage.get_header("Authorization"))
        github=handler.redirect_request(
            request,None,302,"Found",{},"https://api.github.com/redirected"
        )
        self.assertEqual(github.get_header("Authorization"),"Bearer secret-token")

    def test_pull_worker_ignores_corrupt_optional_state(self):
        with tempfile.TemporaryDirectory() as d:
            state=Path(d)/"state.json"
            state.write_text("{broken",encoding="utf-8")
            self.assertEqual(read_state(state),{})
            state.write_text(json.dumps({"schema_version":"future","artifact_id":1}),
                             encoding="utf-8")
            self.assertEqual(read_state(state),{})

    def test_dashboard_artifact_identity_is_source_branch_scoped(self):
        branch="feature/static-code-analysis"
        key=artifact_branch_key(branch)
        self.assertTrue(key.startswith("feature-static-code-analysis-"))
        self.assertEqual(len(key.rsplit("-",1)[1]),12)
        self.assertNotEqual(artifact_branch_key("feature/a-b"),artifact_branch_key("feature-a/b"))
        sha="c37bc75618d44e4a117cc40d20949b37f25ad549"
        name=f"current-findings-dashboard-{key}-{sha}-32945417621"
        self.assertEqual(artifact_commit(name,branch),sha)
        with self.assertRaisesRegex(ValueError,"invalid identity"):
            artifact_commit(f"current-findings-dashboard-{key}-short-1",branch)
        workflow=Path(".github/workflows/05-issue-aggregation.yml").read_text(encoding="utf-8")
        self.assertIn("current-findings-dashboard-${{ steps.snapshot-key.outputs.branch-key }}",workflow)
        self.assertIn('echo "commit-key=${MONITORED_SHA,,}"',workflow)
        self.assertNotIn('urlencode({"branch": branch',
                         Path("scripts/code_analysis/pull_worker.py").read_text(encoding="utf-8"))

    def test_pull_worker_never_publishes_a_late_older_commit_as_current(self):
        branch="feature/example";key=artifact_branch_key(branch)
        current="a"*40;older="b"*40
        responses=[
            {"commit":{"sha":current}},
            {"workflow_runs":[{"id":22},{"id":21}]},
            {"artifacts":[{"id":220,"expired":False,
                            "name":f"current-findings-dashboard-{key}-{older}-22"}]},
            {"artifacts":[{"id":210,"expired":False,
                            "name":f"current-findings-dashboard-{key}-{current}-21"}]},
        ]
        with patch("scripts.code_analysis.pull_worker.request_json",side_effect=responses):
            run,artifact,commit=select_artifact("combustrrr/Agentic-Kibana",branch,"token")
        self.assertEqual(run["id"],21)
        self.assertEqual(artifact["id"],210)
        self.assertEqual(commit,current)

    def test_pull_worker_paginates_busy_multi_branch_history(self):
        branch="feature/rare";key=artifact_branch_key(branch);current="c"*40
        first_page=[{"id":number} for number in range(100)]
        responses=[{"commit":{"sha":current}}, {"workflow_runs":first_page}]
        responses.extend({"artifacts":[]} for _ in first_page)
        responses.extend([
            {"workflow_runs":[{"id":101}]},
            {"artifacts":[{"id":999,"expired":False,
                            "name":f"current-findings-dashboard-{key}-{current}-101"}]},
        ])
        with patch("scripts.code_analysis.pull_worker.request_json",side_effect=responses) as request:
            run,artifact,commit=select_artifact("combustrrr/Agentic-Kibana",branch,"token")
        self.assertEqual((run["id"],artifact["id"],commit),(101,999,current))
        self.assertTrue(any("page=2" in call.args[0] for call in request.call_args_list))

    def test_manual_artifact_selection_requires_successful_aggregator_and_current_head(self):
        branch="feature/manual";commit="d"*40;artifact_id=777
        artifact={"id":artifact_id,"expired":False,
                  "name":f"current-findings-dashboard-{artifact_branch_key(branch)}-{commit}-55",
                  "workflow_run":{"id":55}}
        run={"id":55,"conclusion":"success",
             "path":".github/workflows/05-issue-aggregation.yml"}
        with patch("scripts.code_analysis.pull_worker.request_json",side_effect=[
                artifact,{"commit":{"sha":commit}},run]):
            selected=select_artifact_by_id("combustrrr/Agentic-Kibana",branch,artifact_id,"token")
        self.assertEqual(selected,(run,artifact,commit))

        stale="e"*40
        with patch("scripts.code_analysis.pull_worker.request_json",side_effect=[
                artifact,{"commit":{"sha":stale}}]):
            with self.assertRaisesRegex(RuntimeError,"but latest"):
                select_artifact_by_id("combustrrr/Agentic-Kibana",branch,artifact_id,"token")

    def test_manual_artifact_selection_rejects_wrong_workflow(self):
        branch="feature/manual";commit="f"*40
        artifact={"id":778,"expired":False,
                  "name":f"current-findings-dashboard-{artifact_branch_key(branch)}-{commit}-56",
                  "workflow_run":{"id":56}}
        with patch("scripts.code_analysis.pull_worker.request_json",side_effect=[
                artifact,{"commit":{"sha":commit}},
                {"id":56,"conclusion":"success","path":".github/workflows/01-code-quality.yml"}]):
            with self.assertRaisesRegex(RuntimeError,"not from a successful dashboard"):
                select_artifact_by_id("combustrrr/Agentic-Kibana",branch,778,"token")

    def test_every_branch_uses_exact_pr_head_and_automatic_aggregation(self):
        for name in ("01-code-quality.yml","02-security-sast.yml",
                     "03-dependency-security.yml","04-code-health.yml"):
            workflow=Path(".github/workflows",name).read_text(encoding="utf-8")
            self.assertIn('branches: ["**"]',workflow)
            self.assertNotIn("branches: [claude/main, Testing]",workflow)
            target_checkouts=workflow.count(
                "ref: ${{ inputs.scan_sha || github.event.pull_request.head.sha || github.sha }}")
            tooling_checkouts=workflow.count(
                "ref: ${{ github.event.repository.default_branch }}")
            self.assertGreaterEqual(target_checkouts,1)
            self.assertEqual(workflow.count("uses: actions/checkout@"),
                             target_checkouts+tooling_checkouts)
        aggregate=Path(".github/workflows/05-issue-aggregation.yml").read_text(encoding="utf-8")
        self.assertIn("github.event.workflow_run.event == 'push'",aggregate)
        self.assertIn("github.event.workflow_run.event == 'pull_request'",aggregate)
        self.assertNotIn('contains(fromJSON',aggregate)
        self.assertIn("branch_hash=",aggregate)
        self.assertIn("steps.analysis-artifact.outputs.artifact-id",aggregate)
        self.assertIn("Artifact ID for validated manual recovery",aggregate)

    def test_security_expansion_is_structured_and_runtime_lanes_stay_isolated(self):
        dependency=Path(".github/workflows/03-dependency-security.yml").read_text(encoding="utf-8")
        for marker in ("shipping-image-security:","workflow-security-posture:",
                       "backend.cdx.json","webui.spdx.json","zizmor==1.29.0",
                       "secret_scanning_push_protection","shipping-image-provenance.intoto.json"):
            self.assertIn(marker,dependency)
        self.assertIn("shipping-image-trivy-status.json",dependency)
        self.assertIn("SECURITY_POSTURE_TOKEN",dependency)
        self.assertIn("status=CONFIGURED_PARTIAL",dependency)
        self.assertIn(".snyk-venv/bin/python",dependency)
        self.assertNotIn("secret-scanning-alerts.json",dependency)
        posture=dependency.split("  workflow-security-posture:",1)[1].split(
            "  openssf-scorecard:",1)[0]
        self.assertIn("security-events: write", posture)
        dynamic=Path(".github/workflows/07-api-fuzzing.yml").read_text(encoding="utf-8")
        self.assertIn('cron: "17 4 * * 6"',dynamic)
        self.assertIn("atheris==3.0.0",dynamic)
        self.assertIn("-runs=25000",dynamic)
        self.assertNotIn("\n  pull_request:\n",dynamic)
        model=Path(".github/codeql/extensions/agentic-soc-python/models/security.model.yml")
        self.assertTrue(model.is_file())

    def test_optional_catalog_can_map_native_scanner_family_aliases(self):
        rows=build_additional_channels(
            {"tools":[{"tool":"OpenSSF Scorecard","state":"OPTIONAL_CONFIGURED",
                        "evidence_families":["Scorecard"]}]},None,
            {"observations":[{"scanner_family":"Scorecard"}],"canonical_findings":[],
             "ai_advisories":[]},
        )
        self.assertEqual(rows[0]["status"],"COMPLETED_OPTIONAL")
        self.assertEqual(rows[0]["observation_count"],1)

    def test_one_click_manual_analysis_dispatches_all_scanners(self):
        workflow=Path(".github/workflows/08-full-code-analysis.yml").read_text(encoding="utf-8")
        self.assertIn("workflow_dispatch:",workflow)
        self.assertIn("actions: write",workflow)
        self.assertIn("GH_REPO: ${{ github.repository }}",workflow)
        self.assertNotIn("uses: actions/checkout@",workflow)
        self.assertIn('gh api "repos/${GITHUB_REPOSITORY}/branches/${encoded}"',workflow)
        self.assertIn("WORKFLOW_REF: ${{ github.event.repository.default_branch }}",workflow)
        self.assertIn('gh workflow run "$workflow" --ref "$WORKFLOW_REF"',workflow)
        self.assertNotIn('gh workflow run "$workflow" --ref "$SCAN_BRANCH"',workflow)
        for name in ("01-code-quality.yml","02-security-sast.yml",
                     "03-dependency-security.yml","04-code-health.yml"):
            self.assertIn(name,workflow)
        self.assertIn("displayTitle",workflow)
        self.assertIn(".displayTitle == $title",workflow)
        self.assertNotIn('--commit "$SCAN_SHA"',workflow)
        self.assertIn('-f scan_sha="$SCAN_SHA"',workflow)
        self.assertIn('gh run watch "$run_id" --exit-status',workflow)
        self.assertIn("05-issue-aggregation.yml",workflow)
        self.assertIn('gh run watch "$dashboard_id" --exit-status',workflow)
        self.assertIn("Open dashboard build and download the searchable artifact",workflow)
        self.assertNotIn("issues: write",workflow)
        self.assertNotIn("contents: write",workflow)

    def test_default_branch_supervises_every_latest_fork_branch_head(self):
        workflow=Path(".github/workflows/08-full-code-analysis.yml").read_text(encoding="utf-8")
        self.assertIn('cron: "7,22,37,52 * * * *"',workflow)
        self.assertIn("if: github.event_name == 'schedule'",workflow)
        self.assertIn('gh api --paginate "repos/${GITHUB_REPOSITORY}/branches?per_page=100"',workflow)
        self.assertIn("[.name, .commit.sha] | @tsv",workflow)
        self.assertIn('check_namespace="agentic-soc-current-findings-v1"',workflow)
        self.assertIn('title="Analyze branch · $branch · $sha"',workflow)
        self.assertIn('-f expected_sha="$sha"',workflow)
        self.assertIn('if [[ -n "$EXPECTED_SHA"',workflow)
        self.assertIn("failures >= 3",workflow)
        self.assertNotIn("pull_request_target:",workflow)

    def test_coderabbit_exact_head_comments_are_separate_ai_advisories(self):
        commit="a"*40;repository="combustrrr/Agentic-Kibana";branch="feature/review"
        responses=[
            [{"number":7,"state":"open","head":{"sha":commit,"ref":branch,
              "repo":{"full_name":repository}}}],
            [{"id":11,"commit_id":commit,"user":{"login":"coderabbitai[bot]"}}],
            [{"id":21,"commit_id":commit,"in_reply_to_id":None,
              "user":{"login":"coderabbitai[bot]"},"path":"backend/app/api/routes.py",
              "line":42,"body":"Potential major authorization issue",
              "html_url":"https://github.com/combustrrr/Agentic-Kibana/pull/7#discussion_r21"},
             {"id":22,"commit_id":"b"*40,"in_reply_to_id":None,
              "user":{"login":"coderabbitai[bot]"},"path":"old.py","line":1,
              "body":"stale","html_url":"https://github.com/example"}],
        ]
        with patch("scripts.code_analysis.collect_coderabbit.request_json",side_effect=responses):
            evidence,status=collect_coderabbit(repository,branch,commit,"token")
        self.assertEqual(status["status"],"COMPLETED_OPTIONAL")
        self.assertEqual(len(evidence["advisories"]),1)
        with tempfile.TemporaryDirectory() as d:
            path=Path(d)/"coderabbit-advisories.json"
            path.write_text(json.dumps(evidence),encoding="utf-8")
            parsed=CodeRabbitParser().parse(path)
        self.assertEqual(parsed[0].evidence_source,"AI_ADVISORY")
        self.assertEqual(parsed[0].severity,"HIGH")
        current=canonicalize([parsed[0].__dict__, raw()],repository,RUN,MANIFEST)
        lanes={row["evidence_source"] for row in current["findings"]}
        self.assertEqual(lanes,{"AI_ADVISORY","DETERMINISTIC"})
        aggregate=Path(".github/workflows/05-issue-aggregation.yml").read_text(encoding="utf-8")
        self.assertIn("pull-requests: read",aggregate)
        self.assertIn("collect_coderabbit.py",aggregate)
        refresh=Path(".github/workflows/09-coderabbit-advisory-refresh.yml").read_text(encoding="utf-8")
        self.assertIn("pull_request_review:",refresh)
        self.assertIn("GH_REPO: ${{ github.repository }}",refresh)
        self.assertNotIn("uses: actions/checkout@",refresh)
        self.assertIn("github.event.review.commit_id == github.event.pull_request.head.sha",refresh)
        self.assertIn("09-coderabbit-advisory-refresh",str(Path(".github/workflows/09-coderabbit-advisory-refresh.yml")))
        self.assertNotIn("issues: write",refresh)
        self.assertNotIn("contents: write",refresh)

if __name__=="__main__": unittest.main()
