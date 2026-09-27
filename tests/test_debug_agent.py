import json
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

import sys
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import debug_agent


class DebugAgentTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.repo = self.root / "repo"
        self.repo.mkdir()
        (self.repo / "app.py").write_text("def average(values):\n    return sum(values) / len(values)\n", encoding="utf-8")
        (self.repo / "requirements.txt").write_text("requests==2.0\n", encoding="utf-8")
        self.log = self.root / "error.log"
        self.log.write_text("2026-09-26 10:00:00 ERROR average failed\nZeroDivisionError: division by zero\n", encoding="utf-8")
        self.output = self.root / "report.md"

    def run_cli(self, log=None, issue="average failed"):
        return debug_agent.main(["--repo", str(self.repo), "--logs", str(log or self.log),
                                 "--issue", issue, "--output", str(self.output), "--timeout", "1"])

    def test_normal_case_and_unchanged_repo(self):
        before = {p.name: p.read_bytes() for p in self.repo.iterdir()}
        diagnosis = {"root_cause": "Empty input causes division by zero", "confidence": "high",
                     "evidence": [{"path": "app.py", "line": 2, "reason": "Denominator is zero"}],
                     "fix": "Handle empty lists", "diff": "--- a/app.py\n+++ b/app.py\n@@ -1,2 +1,4 @@\n def average(values):\n+    if not values:\n+        return 0\n     return sum(values) / len(values)"}
        with patch.object(debug_agent, "ollama_chat", return_value=diagnosis):
            self.assertEqual(self.run_cli(), 0)
        result = json.loads(self.output.with_suffix(".md.json").read_text())
        self.assertEqual(result["status"], "complete")
        self.assertIn("ZeroDivisionError", self.output.read_text())
        self.assertEqual(before, {p.name: p.read_bytes() for p in self.repo.iterdir()})

    def test_missing_logs_and_unavailable_model(self):
        with patch.object(debug_agent, "ollama_chat", side_effect=TimeoutError("offline")):
            self.run_cli(self.root / "missing.log")
        result = json.loads(self.output.with_suffix(".md.json").read_text())
        self.assertEqual(result["status"], "incomplete")
        self.assertEqual(result["logs"]["status"], "missing")
        self.assertTrue(result["code"]["matches"])

    def test_no_matching_code(self):
        self.log.write_text("ERROR unrelatedxyz\n", encoding="utf-8")
        with patch.object(debug_agent, "ollama_chat", side_effect=TimeoutError("offline")):
            self.run_cli(issue="unrelatedxyz")
        result = json.loads(self.output.with_suffix(".md.json").read_text())
        self.assertEqual(result["code"]["matches"], [])

    def test_invalid_evidence_and_diff_are_rejected(self):
        diagnosis = {"root_cause": "Guess", "confidence": "low",
                     "evidence": [{"path": "../secret", "line": 1, "reason": "wrong"}],
                     "fix": "Guess", "diff": "--- a/app.py\n+++ b/app.py\n@@ -1,1 +1,1 @@\n-not present\n+replacement"}
        with patch.object(debug_agent, "ollama_chat", return_value=diagnosis):
            self.run_cli()
        result = json.loads(self.output.with_suffix(".md.json").read_text())
        self.assertEqual(result["status"], "needs_review")
        self.assertEqual(result["diagnosis"]["diff"], "")
        self.assertEqual(result["diagnosis"]["evidence"], [])

    def test_stack_frame_ranks_first_and_redacts_secret(self):
        self.log.write_text('ERROR password=supersecret\n  File "app.py", line 2, in average\nZeroDivisionError: division by zero\n', encoding="utf-8")
        (self.repo / "app.py").write_text('token = "hidden"\ndef average(values):\n    return sum(values) / len(values)\n', encoding="utf-8")
        with patch.object(debug_agent, "ollama_chat", side_effect=TimeoutError("offline")):
            self.run_cli(issue="division by zero")
        result = json.loads(self.output.with_suffix(".md.json").read_text())
        self.assertEqual(result["code"]["matches"][0]["line"], 2)
        self.assertNotIn("supersecret", self.output.read_text())
        self.assertNotIn("hidden", self.output.read_text())

    def test_output_inside_repo_is_rejected(self):
        with self.assertRaises(SystemExit):
            debug_agent.main(["--repo", str(self.repo), "--logs", str(self.log),
                              "--output", str(self.repo / "report.md")])
        self.assertFalse((self.repo / "report.md").exists())

    def test_skip_model_creates_evidence_ready_report(self):
        with patch.object(debug_agent, "ollama_chat") as model:
            debug_agent.main(["--repo", str(self.repo), "--logs", str(self.log),
                              "--issue", "average failed", "--output", str(self.output),
                              "--skip-model"])
        model.assert_not_called()
        result = json.loads(self.output.with_suffix(".md.json").read_text())
        self.assertEqual(result["status"], "evidence_ready")
        self.assertIn("Evidence ready for IBM Bob", self.output.read_text())

    def test_summary_uses_deepest_stack_frame(self):
        self.log.write_text(
            'Traceback (most recent call last):\n  File "app.py", line 1, in run\n'
            '  File "app.py", line 2, in average\nZeroDivisionError: division by zero\n',
            encoding="utf-8")
        debug_agent.main(["--repo", str(self.repo), "--logs", str(self.log),
                          "--issue", "empty list", "--output", str(self.output), "--skip-model"])
        result = json.loads(self.output.with_suffix(".md.json").read_text())
        self.assertEqual(result["summary"]["likely_fault"], {"path": "app.py", "line": 2})
        self.assertIn("ZeroDivisionError", result["summary"]["exception"])
        self.assertIn("empty collection", result["summary"]["preliminary_diagnosis"])

    def test_validation_runs_in_copy_and_reports_expected_failure(self):
        tests = self.repo / "tests"
        tests.mkdir()
        (tests / "test_known_bug.py").write_text(
            "import unittest\n"
            "class KnownBug(unittest.TestCase):\n"
            "    @unittest.expectedFailure\n"
            "    def test_bug(self): self.assertEqual(1, 2)\n",
            encoding="utf-8")
        before = sorted(p.relative_to(self.repo) for p in self.repo.rglob("*"))
        debug_agent.main(["--repo", str(self.repo), "--logs", str(self.log),
                          "--issue", "known bug", "--output", str(self.output), "--skip-model",
                          "--test-command", "python -m unittest discover -s tests -v"])
        result = json.loads(self.output.with_suffix(".md.json").read_text())
        self.assertEqual(result["test_validation"]["status"], "passed_with_expected_failures")
        self.assertEqual(before, sorted(p.relative_to(self.repo) for p in self.repo.rglob("*")))
        self.assertIn("total", result["timings_ms"])

    def test_cross_domain_findings_are_prioritized(self):
        (self.repo / "app.py").write_text(
            "import subprocess\n"
            "def average(values):\n"
            "    subprocess.run('tool ' + str(values), shell=True)\n"
            "    return sum(values) / len(values)\n",
            encoding="utf-8")
        self.log.write_text(
            'Traceback (most recent call last):\n  File "app.py", line 4, in average\n'
            'ZeroDivisionError: division by zero\n', encoding="utf-8")
        debug_agent.main(["--repo", str(self.repo), "--logs", str(self.log),
                          "--issue", "empty values", "--output", str(self.output), "--skip-model"])
        result = json.loads(self.output.with_suffix(".md.json").read_text())
        categories = {item["category"] for item in result["findings"]}
        self.assertIn("security", categories)
        self.assertIn("correctness", categories)
        correlated = next(item for item in result["findings"] if item["category"] == "correctness")
        self.assertEqual(correlated["status"], "highly_likely")
        self.assertEqual(result["scan_parameters"]["max_files"], debug_agent.MAX_FILES)


if __name__ == "__main__":
    unittest.main()
