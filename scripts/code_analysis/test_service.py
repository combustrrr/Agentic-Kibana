import json, tempfile, unittest
from argparse import Namespace
from datetime import datetime, timezone
from pathlib import Path
from unittest.mock import patch
from click.testing import CliRunner
from scripts.code_analysis.audit_workflows import audit as audit_workflows, audit_runtime_isolation
from scripts.code_analysis.bound_sarif import bound as bound_sarif
from scripts.code_analysis.channel_status import build as build_channel_status
from scripts.code_analysis.collect_coderabbit import collect as collect_coderabbit
from scripts.code_analysis.dashboard import artifact_readme, generate, github_summary, validate_snapshot, write_dashboard
from scripts.code_analysis.evidence_contract import build as build_evidence_contract
from scripts.code_analysis.export_sonar_issues import export as export_sonar_issues
from scripts.code_analysis.monitoring import EvidenceError, build_snapshot, canonicalize, check_key, compare, effective_triage, scanner_family, stable_id
from scripts.code_analysis.normalizer import CodeRabbitParser, CoverageParser, Finding, RadonParser, SarifParser, SchemathesisParser, SonarExternalIssuesExporter, SonarParser, TscParser, XenonParser, main as normalize_cli, normalize_concept
from scripts.code_analysis.pipeline import build as build_pipeline
from scripts.code_analysis.provenance import build as build_provenance
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
    def test_sonar_export_queries_projection_branch_but_retains_git_identity(self):
        calls = []

        def request(url, _token):
            calls.append(url)
            if "ce/task" in url:
                return {"task": {"status": "SUCCESS", "analysisId": "analysis-1"}}
            return {"issues": [], "paging": {"total": 0}}

        with tempfile.TemporaryDirectory() as d, patch(
            "scripts.code_analysis.export_sonar_issues._request", side_effect=request
        ):
            root = Path(d)
            task = root / "report-task.txt"
            task.write_text(
                "serverUrl=https://sonarcloud.io\n"
                "ceTaskUrl=https://sonarcloud.io/api/ce/task?id=1\n"
                "projectKey=org_repo\n",
                encoding="utf-8",
            )
            output = root / "issues.json"
            result = export_sonar_issues(
                task,
                output,
                "org_repo",
                "feature/source",
                "a" * 40,
                "token",
                sonar_branch="branch-issue-wall-1234",
            )
            self.assertEqual(result["branch"], "feature/source")
            self.assertEqual(result["sonar_branch"], "branch-issue-wall-1234")
            self.assertIn("branch=branch-issue-wall-1234", calls[-1])

    def test_sonar_native_import_and_external_projection_boundaries(self):
        native = {"schema_version": "1", "project_key": "org_repo", "branch": "feature",
                  "commit": "a" * 40, "issues": [
                      {"key": "native-1", "rule": "python:S123", "component": "org_repo:backend/app/a.py",
                       "message": "Native issue", "severity": "MAJOR", "line": 7,
                       "textRange": {"startLine": 7, "endLine": 7, "startOffset": 2, "endOffset": 6}},
                      {"key": "loop", "rule": "external_issue-wall:R1", "external": True,
                       "component": "org_repo:backend/app/a.py", "message": "Do not loop", "line": 8}]}
        with tempfile.TemporaryDirectory() as d:
            root = Path(d)
            source = root / "sonar-native-issues.json"
            source.write_text(json.dumps(native), encoding="utf-8")
            parsed = SonarParser().parse(source)
            self.assertEqual(len(parsed), 1)
            self.assertEqual(parsed[0].file, "backend/app/a.py")
            self.assertEqual(parsed[0].source_tool, "SonarQube Cloud")

            deterministic = Finding(source_tool="Ruff", file="backend/app/b.py", start_line=3,
                                    end_line=3, rule_id="E501", rule_name="line length",
                                    message="too long", severity="LOW", category="QUALITY")
            advisory = Finding(source_tool="CodeRabbit", file="backend/app/c.py", start_line=4,
                               rule_id="review", message="consider this", severity="INFO",
                               category="AI_REVIEW", evidence_source="AI_ADVISORY")
            output = root / "projection.json"
            SonarExternalIssuesExporter().export([parsed[0], deterministic, advisory], output)
            projection = json.loads(output.read_text(encoding="utf-8"))
            self.assertEqual([row["ruleId"] for row in projection["issues"]], ["Ruff:E501"])

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
        self.assertTrue(_denied_license("GPL-2.0+"))
        self.assertTrue(_denied_license("gpl-2.0-only"))

    def test_shipping_image_sarif_uses_its_optional_scanner_family(self):
        with tempfile.TemporaryDirectory() as d:
            sarif_path=Path(d)/"trivy-backend-image.sarif"
            sarif_path.write_text(json.dumps({"runs":[{"tool":{"driver":{"name":"Trivy"}},
                "results":[{"ruleId":"CVE-1","message":{"text":"image issue"}}]}]}),
                encoding="utf-8")
            findings=SarifParser().parse(sarif_path,tool_override="Shipping Image Trivy")
            self.assertEqual(findings[0].source_tool,"Shipping Image Trivy")

    def test_snyk_code_driver_and_rules_use_canonical_snyk_identity(self):
        self.assertEqual(scanner_family("SnykCode"), "Snyk")
        expected = {
            "python/NoHardcodedPasswords/test": "hardcoded-secret",
            "javascript/HardcodedNonCryptoSecret": "hardcoded-secret",
            "python/CommandInjection": "command-injection",
            "python/InsecureHash": "weak-crypto",
            "python/PT": "path-traversal",
            "python/TarSlip/test": "path-traversal",
            "javascript/OR": "open-redirect",
        }
        self.assertEqual({rule: normalize_concept(rule) for rule in expected}, expected)

    def test_dashboard_is_bounded_and_exposes_all_current_findings(self):
        result=snapshot([raw("CodeQL"),raw("Semgrep")])
        with tempfile.TemporaryDirectory() as d:
            output=Path(d)/"index.html";generate(result,output);page=output.read_text()
            self.assertIn("Actionable canonical findings",page);self.assertIn("Show all priorities",page)
            self.assertIn("slice((page-1)*size,page*size)",page)
            self.assertIn("searchIndex.get(x.stable_id)",page)
            self.assertIn("Raw evidence records",page);self.assertIn("Issue Wall",github_summary(result))
            self.assertIn("dashboard/index.html",github_summary(result))
            self.assertIn("Start here — Issue Wall",artifact_readme(result))
            self.assertIn("Two-minute review walkthrough",artifact_readme(result))
            self.assertIn("Snapshot ID",artifact_readme(result))
            self.assertIn("Snapshot integrity and source proof",page)
            self.assertIn("artifactHashes",page)
            self.assertIn("Security focus",page)
            self.assertIn("Security findings",page)
            self.assertIn("securityFinding",page)
            self.assertIn("mode==='ai'?'AI advisory'",page)
            self.assertIn("Analysis overview",page)
            self.assertIn("Highest-risk areas",page)
            self.assertIn("Publication path",page)
            self.assertIn("Issue Wall",page)
            self.assertIn("Web of Scanners",page)
            self.assertIn("Run Web of Scanners",page)
            self.assertIn("08-full-code-analysis.yml",page)
            self.assertIn("Build Issue Wall",page)
            self.assertIn("05-issue-aggregation.yml",page)
            self.assertIn('class="action-card primary"', page)
            self.assertIn("Select a branch and analyze its latest head commit", page)
            self.assertIn("GitHub-controlled", page)
            self.assertIn("read-only analysis", page)
            self.assertIn("Run another analysis", page)
            self.assertIn("--pink:#f472b6", page)
            self.assertIn("radial-gradient", page)
            self.assertIn("Fix queue",page)
            self.assertIn("data-wall-severity",page)
            self.assertIn("data-filter",page)
            self.assertIn("copyLink",page)
            self.assertIn("Developer findings report",page)
            self.assertIn("Risk distribution",page)
            self.assertIn("Top affected files",page)
            self.assertIn("Where to start",page)
            self.assertIn("Export filtered CSV",page)
            self.assertIn("Copy location",page)
            self.assertIn("Why this needs attention",page)
    def test_dashboard_artifact_includes_offline_launch_guide(self):
        result=snapshot([raw("CodeQL"),raw("Semgrep")])
        with tempfile.TemporaryDirectory() as d:
            write_dashboard(result,Path(d))
            guide=(Path(d)/"START_HERE.md").read_text(encoding="utf-8")
            self.assertIn("dashboard/index.html",guide)
            self.assertIn(result["commit_sha"],guide)
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
        self.assertEqual(audit_runtime_isolation(),[])
        for retired in ("scripts/code_analysis/local_service.py",
                        "scripts/code_analysis/pull_worker.py",
                        "scripts/code_analysis/publish_snapshot.py",
                        "deploy/code-analysis-dashboard","web-of-scanners.ps1"):
            self.assertFalse(Path(retired).exists(),retired)
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

    def test_product_runtime_cannot_depend_on_external_analysis_service(self):
        import scripts.code_analysis.audit_workflows as policy
        with tempfile.TemporaryDirectory() as directory:
            root=Path(directory)
            (root/"backend/app").mkdir(parents=True)
            (root/"backend/app/main.py").write_text(
                "from scripts.code_analysis.dashboard import generate\n",encoding="utf-8")
            with patch.object(policy,"ROOT",root), patch.object(
                    policy,"RUNTIME_BOUNDARY_FILES",()):
                errors=policy.audit_runtime_isolation()
        self.assertEqual(len(errors),1)
        self.assertIn("must not depend on external code analysis",errors[0])

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

    def test_snapshot_reconciles_findings_and_observations(self):
        result=snapshot([raw("CodeQL"),raw("Semgrep")])
        self.assertTrue(result["publishable"]);self.assertEqual(result["finding_count"],1)
        self.assertEqual(result["observation_count"],2);validate_snapshot(result)

    def test_snapshot_rejects_incomplete_channels_and_mixed_commit(self):
        with self.assertRaises(EvidenceError): snapshot(channel_state=status(semgrep="FAILED"))
        current=evidence([raw()]);provenance={"commit_sha":"other","workflow_run_ids":["1"],"artifact_hashes":[{"path":"a","sha256":"a"*64}]}
        with self.assertRaises(EvidenceError): build_snapshot(current,status(),provenance)

    def test_provenance_hashes_and_artifact_bundle(self):
        with tempfile.TemporaryDirectory() as d:
            root=Path(d);artifacts=root/"artifacts";artifacts.mkdir();(artifacts/"a.json").write_text("one")
            provenance=build_provenance(artifacts,"abc",["1"]);self.assertEqual(len(provenance["artifact_hashes"][0]["sha256"]),64)
            bundle=root/"dashboard";write_dashboard(snapshot(),bundle)
            self.assertTrue((bundle/"index.html").is_file())
            self.assertTrue((bundle/"START_HERE.md").is_file())

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

    def test_scanners_collect_automatically_but_dashboard_is_manual_only(self):
        monitored='branches: ["**"]'
        for name in ("01-code-quality.yml","02-security-sast.yml",
                     "03-dependency-security.yml","04-code-health.yml"):
            workflow=Path(".github/workflows",name).read_text(encoding="utf-8")
            self.assertIn(monitored,workflow)
        aggregator=Path(".github/workflows/05-issue-aggregation.yml").read_text(encoding="utf-8")
        self.assertIn("workflow_call:",aggregator)
        self.assertNotIn("workflow_run:",aggregator)
        self.assertNotIn("workflow_dispatch:",aggregator)
        self.assertNotIn("schedule:",aggregator)
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

    def test_integrated_tools_are_explicitly_accounted_for(self):
        catalog=json.loads(Path("config/code-analysis/proposal-tool-catalog.json").read_text(encoding="utf-8"))
        tools={row["tool"]:row for row in catalog["tools"]}
        selected={"CodeRabbit","CodeQL","Semgrep","Bandit","Ruff","Pyright","ESLint","TypeScript","OSV-Scanner","Snyk","Gitleaks","Trivy","Schemathesis","Atheris","SonarQube Cloud"}
        self.assertTrue(selected.issubset(tools))
        required=json.loads(Path("config/code-analysis/required-channels.json").read_text(encoding="utf-8"))
        channels={row["channel"] for row in required["required_static_channels"]}
        for row in tools.values():
            if row["state"] == "ACTIVE_REQUIRED": self.assertIn(row["channel"],channels)

    def test_shared_pipeline_builds_artifact_bundle(self):
        with tempfile.TemporaryDirectory() as d:
            root=Path(d);artifacts=root/"artifacts";artifacts.mkdir()
            (artifacts/"codeql.sarif").write_text(json.dumps({"version":"2.1.0","runs":[]}),encoding="utf-8")
            (artifacts/"semgrep.json").write_text('{"results":[]}',encoding="utf-8")
            (artifacts/"snyk-status.json").write_text(json.dumps({
                "schema_version":"1","scanner_family":"Snyk",
                "status":"CONFIGURED_COMPLETE","surfaces":{"sca":"success","code":"success"}
            }),encoding="utf-8")
            (artifacts/"coderabbit-status.json").write_text(json.dumps({
                "schema_version":"1","scanner_family":"CodeRabbit",
                "status":"NOT_APPLICABLE","reason":"no exact-head review evidence"
            }),encoding="utf-8")
            manifest=root/"manifest.json";manifest.write_text(json.dumps(MANIFEST),encoding="utf-8")
            output=root/"run"
            build_pipeline(Namespace(artifacts=artifacts,output=output,repository="repo/fork",commit="abc",
                                     branch="feature",workflow_run_id=["1"],manifest=manifest))
            self.assertTrue((output/"normalized"/"current-snapshot.json").is_file())
            self.assertTrue((output/"dashboard"/"index.html").is_file())
            current=json.loads((output/"normalized"/"current-snapshot.json").read_text(encoding="utf-8"))
            additional={row["tool"]:row for row in current["additional_channels"]}
            self.assertEqual(additional["Snyk"]["status"],"CONFIGURED_COMPLETE")
            self.assertEqual(additional["CodeRabbit"]["status"],"NOT_APPLICABLE")
            self.assertEqual(additional["CodeRabbit"]["evidence_source"],"AI_ADVISORY")
            dashboard=(output/"dashboard"/"index.html").read_text(encoding="utf-8")
            self.assertIn("Security controls &amp; optional assurance",dashboard)
            self.assertIn("Operational assurance",dashboard)
            self.assertIn("Required scanner evidence",dashboard)
            self.assertIn("Critical and high review queue",dashboard)
            self.assertIn("Scanner distribution",dashboard)
            self.assertIn("Actionable Issues",dashboard)
            self.assertIn("actionableOnly=true",dashboard)
            self.assertIn("Exact commit SHA",dashboard)
            self.assertIn("identityBranch",dashboard)
            self.assertIn("/blob/${data.commit_sha}/",dashboard)
            self.assertIn("base.sort(severitySort)",dashboard)

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
            output=root/"output"
            build_pipeline(Namespace(
                artifacts=artifacts,output=output,
                repository="combustrrr/Agentic-Kibana",commit="a"*40,
                branch="Testing",workflow_run_id=["1","2","3","4"],
                manifest=Path("config/code-analysis/required-channels.json"),
                tool_catalog=Path("config/code-analysis/proposal-tool-catalog.json"),
            ))
            channel_status=json.loads((output/"channel-status.json").read_text(encoding="utf-8"))
            snapshot=json.loads((output/"normalized/current-snapshot.json").read_text(encoding="utf-8"))
            self.assertEqual(len(channel_status["channels"]),16)
            self.assertTrue(all(row["status"] == "COMPLETED"
                                for row in channel_status["channels"]))
            self.assertTrue(snapshot["publishable"])
            self.assertEqual(snapshot["finding_count"],0)
            self.assertTrue((output/"dashboard/index.html").is_file())

    def test_every_branch_uses_exact_pr_head_and_manual_aggregation(self):
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
        self.assertIn("workflow_call:",aggregate)
        self.assertNotIn("github.event.workflow_run",aggregate)
        self.assertNotIn('contains(fromJSON',aggregate)
        self.assertIn("branch_hash=",aggregate)
        self.assertIn("steps.analysis-artifact.outputs.artifact-id",aggregate)
        self.assertIn("Artifact ID for validated manual recovery",aggregate)
        self.assertIn("declare -A run_ids=()", aggregate)
        self.assertIn("One shared deadline keeps the four-workflow handoff bounded", aggregate)
        self.assertEqual(aggregate.count("for attempt in $(seq 1 40)"), 1)

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
        self.assertIn("github.ref_name == github.event.repository.default_branch",dependency)
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
        self.assertNotIn("discover-latest-branch-heads",workflow)
        self.assertNotIn("github.event_name == 'schedule'",workflow)
        self.assertIn('default: ""',workflow)
        self.assertIn('branch="${REQUESTED_BRANCH:-$GITHUB_DEFAULT_BRANCH}"',workflow)
        self.assertIn("github.event.repository.default_branch",workflow)
        self.assertIn("inputs.scan_sha",workflow)
        self.assertIn("Specific SHA must contain exactly 40 hexadecimal characters",workflow)
        self.assertIn('compare/${sha}...${head_sha,,}',workflow)
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
        self.assertIn("Review-ready artifact handoff",workflow)
        self.assertIn("needs.dashboard.outputs.artifact_url",workflow)
        self.assertIn("No VM, server, installation, or network connection",workflow)
        aggregate=Path(".github/workflows/05-issue-aggregation.yml").read_text(encoding="utf-8")
        self.assertIn("artifact_digest:",aggregate)
        self.assertIn("jobs.aggregate.outputs.artifact_digest",aggregate)
        self.assertNotIn('--commit "$SCAN_SHA"',workflow)
        self.assertIn('-f scan_sha="$SCAN_SHA"',workflow)
        self.assertIn('gh run watch "$run_id" --interval 15 --exit-status',workflow)
        self.assertIn('pids+=("$!")', workflow)
        self.assertIn("reused exact-commit evidence", workflow)
        self.assertIn("actions/runs/${run_id}/artifacts", workflow)
        self.assertIn("Web of Scanners · live pipeline", workflow)
        self.assertIn("cancel-in-progress: true", workflow)
        self.assertIn("05-issue-aggregation.yml",workflow)
        self.assertIn("uses: ./.github/workflows/05-issue-aggregation.yml",workflow)
        self.assertIn("Build exact-commit Issue Wall artifact",workflow)
        self.assertNotIn("issues: write",workflow)
        self.assertNotIn("contents: write",workflow)
        aggregation=Path(".github/workflows/05-issue-aggregation.yml").read_text(encoding="utf-8")
        self.assertIn('--status success --limit 30',aggregation)
        self.assertNotIn('--event workflow_dispatch --status success',aggregation)

    def test_issue_wall_has_no_automatic_or_scheduled_publication_path(self):
        workflow=Path(".github/workflows/08-full-code-analysis.yml").read_text(encoding="utf-8")
        self.assertNotIn('\n  schedule:\n',workflow)
        aggregate=Path(".github/workflows/05-issue-aggregation.yml").read_text(encoding="utf-8")
        self.assertNotIn("workflow_run:",aggregate)
        self.assertNotIn("workflow_dispatch:",aggregate)
        refresh=Path(".github/workflows/09-coderabbit-advisory-refresh.yml").read_text(encoding="utf-8")
        self.assertIn("pull_request_review:",refresh)
        self.assertNotIn("github.event.review.commit_id == github.event.pull_request.head.sha",refresh)
        self.assertIn("github.event.pull_request.head.repo.full_name == github.repository",refresh)
        self.assertNotIn("gh workflow run 05-issue-aggregation.yml",refresh)
        self.assertNotIn("actions: write",refresh)
        self.assertNotIn("pull_request_target:",workflow)

    def test_latest_branch_head_supersedes_stale_analysis_work(self):
        groups = {
            "01-code-quality.yml": "code-quality-",
            "02-security-sast.yml": "security-sast-",
            "03-dependency-security.yml": "dependency-security-",
            "04-code-health.yml": "code-health-",
            "05-issue-aggregation.yml": "issue-wall-",
        }
        for name, prefix in groups.items():
            workflow = Path(".github/workflows", name).read_text(encoding="utf-8")
            self.assertIn(f"group: {prefix}", workflow)
            self.assertIn("cancel-in-progress: true", workflow)
            self.assertIn("inputs.scan_branch", workflow)

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
        self.assertIn("issue_comment:",refresh)
        self.assertIn("Review finished",refresh)
        self.assertNotIn("github.event.review.commit_id == github.event.pull_request.head.sha",refresh)
        self.assertIn("collect_coderabbit.py",refresh)
        self.assertIn("coderabbit-advisory-evidence-",refresh)
        self.assertNotIn("gh workflow run 05-issue-aggregation.yml",refresh)
        self.assertNotIn("actions: write",refresh)
        self.assertNotIn("issues: write",refresh)
        self.assertNotIn("contents: write",refresh)

    def test_coderabbit_exact_head_success_status_proves_clean_review(self):
        commit="c"*40;repository="combustrrr/Agentic-Kibana";branch="feature/clean"
        responses=[
            [{"number":8,"state":"open","head":{"sha":commit,"ref":branch,
              "repo":{"full_name":repository}}}],
            [],
            [],
            {"statuses":[{"context":"CodeRabbit","state":"success",
                           "description":"Review completed"}]},
        ]
        with patch("scripts.code_analysis.collect_coderabbit.request_json",side_effect=responses):
            evidence,status=collect_coderabbit(repository,branch,commit,"token")
        self.assertEqual(status["status"],"COMPLETED_OPTIONAL")
        self.assertEqual(status["finding_count"],0)
        self.assertEqual(evidence["completion_signals"],["exact-head-success-status"])

    def test_coderabbit_rate_limit_status_is_not_completion_evidence(self):
        commit="d"*40;repository="combustrrr/Agentic-Kibana";branch="feature/limited"
        responses=[
            [{"number":9,"state":"open","head":{"sha":commit,"ref":branch,
              "repo":{"full_name":repository}}}], [], [],
            {"statuses":[{"context":"CodeRabbit","state":"success",
                           "description":"Review rate limited"}]},
        ]
        with patch("scripts.code_analysis.collect_coderabbit.request_json",side_effect=responses):
            evidence,status=collect_coderabbit(repository,branch,commit,"token")
        self.assertEqual(status["status"],"NOT_APPLICABLE")
        self.assertEqual(evidence["completion_signals"],[])

if __name__=="__main__": unittest.main()
