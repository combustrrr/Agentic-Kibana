import unittest
import json
import tempfile
from pathlib import Path

from scripts.code_analysis.dashboard import coverage_manifest, generate
from scripts.code_analysis.issue_sync import build_plan
from scripts.code_analysis.normalizer import Finding, FindingDeduplicator, canonicalize_file


class NormalizerServiceTests(unittest.TestCase):
    def test_absolute_paths_are_repository_relative(self):
        self.assertEqual(canonicalize_file("/home/runner/work/repo/repo/backend/app/a.py"), "backend/app/a.py")
        self.assertEqual(canonicalize_file(r"C:\repo\webui\src\a.ts"), "webui/src/a.ts")

    def test_tools_deduplicate_by_location_and_concept(self):
        first = Finding(source_tool="Bandit", file="backend/app/a.py", start_line=7, rule_id="B608", severity="HIGH")
        second = Finding(source_tool="Semgrep", file="./backend/app/a.py", start_line=7, rule_id="python/sql-injection", severity="MEDIUM")
        canonical = [item for item in FindingDeduplicator().deduplicate([first, second]) if not item.is_duplicate]
        self.assertEqual(len(canonical), 1)
        self.assertIn("Semgrep", canonical[0].evidence[0])

    def test_issue_plan_is_idempotent_and_never_closes(self):
        finding = {"id": "abc123", "severity": "HIGH", "file": "backend/a.py", "start_line": 4,
                   "rule_concept": "sql-injection", "rule_id": "B608", "source_tool": "Bandit",
                   "message": "unsafe query", "evidence": []}
        plan = build_plan([finding], [{"body": "<!-- code-analysis-fingerprint:abc123 -->", "labels": []}], {"HIGH"}, 25)
        self.assertEqual(plan["create"], [])
        self.assertFalse(plan["close_issues"])

    def test_issue_plan_obeys_severity_and_creation_cap(self):
        findings = [{"id": str(i), "severity": "HIGH", "file": f"f{i}.py", "start_line": i,
                     "rule_concept": "x", "rule_id": "x", "source_tool": "Tool", "message": "m",
                     "evidence": []} for i in range(3)]
        plan = build_plan(findings, [], {"HIGH"}, 2)
        self.assertEqual(len(plan["create"]), 2)
        self.assertEqual(plan["deferred_by_limit"], 1)

    def test_vulture_text_and_dashboard_include_all_findings(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            report = root / "vulture-results.txt"
            report.write_text("backend/app/a.py:12: unused function 'old' (90% confidence)\n", encoding="utf-8")
            from scripts.code_analysis.normalizer import VultureParser
            findings = VultureParser().parse_text(report)
            self.assertEqual(len(findings), 1)
            serialized = [findings[0].__dict__]
            manifest = coverage_manifest(root, serialized)
            output = root / "index.html"
            generate(serialized, manifest, {"status": "missing"}, output)
            page = output.read_text(encoding="utf-8")
            self.assertIn("backend/app/a.py", page)
            self.assertIn("Every normalized finding", page)

    def test_semgrep_pyright_and_eslint_json_are_ingested(self):
        from scripts.code_analysis.normalizer import EslintParser, PyrightParser, SemgrepParser
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            semgrep = root / "semgrep.json"
            semgrep.write_text(json.dumps({"results": [{"check_id": "python/sql-injection", "path": "backend/a.py",
                "start": {"line": 3, "col": 1}, "end": {"line": 3, "col": 4},
                "extra": {"severity": "ERROR", "message": "unsafe", "metadata": {"cwe": ["CWE-89"]}}}]}))
            pyright = root / "pyright.json"
            pyright.write_text(json.dumps({"generalDiagnostics": [{"file": "backend/a.py", "severity": "error",
                "message": "bad type", "rule": "reportType", "range": {"start": {"line": 1, "character": 0},
                "end": {"line": 1, "character": 2}}}]}))
            eslint = root / "eslint.json"
            eslint.write_text(json.dumps([{"filePath": "webui/src/a.ts", "messages": [{"ruleId": "no-eval",
                "severity": 2, "message": "eval", "line": 4, "column": 1}]}]))
            self.assertEqual(len(SemgrepParser().parse(semgrep)), 1)
            self.assertEqual(PyrightParser().parse(pyright)[0].start_line, 2)
            self.assertEqual(len(EslintParser().parse(eslint)), 1)


if __name__ == "__main__":
    unittest.main()
