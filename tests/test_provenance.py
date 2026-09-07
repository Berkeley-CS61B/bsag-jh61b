"""Infrastructure tests only: fake callbacks do not implement tampering checks.

Run with: python -m unittest discover -s tests -v
"""

import json
import os
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import Mock, patch

import yaml
from bsag import BaseStepConfig, BaseStepDefinition
from bsag._logging import StepLogs
from bsag.bsag import BSAG, get_plugin_manager
from bsag.bsagio import BSAGIO
from bsag.steps.gradescope import RESULTS_KEY, Results
from bsag.steps.gradescope.results import ResultsConfig, WriteResults
from loguru import logger

from bsag_jh61b._types import TEST_RESULTS_KEY, Jh61bResults
from bsag_jh61b.final_score import FinalScore, FinalScoreConfig
from bsag_jh61b.provenance import PROVENANCE_REPORT_KEY, Provenance, ProvenanceConfig
from bsag_jh61b.provenance_verify import (
    CHECKS,
    CheckResult,
    Finding,
    Report,
    SubmissionReader,
    VerificationUnavailable,
    verify_assignment,
)

PACKAGE = Path(__file__).resolve().parents[1]
COURSE = PACKAGE.parent / "course-materials-fa26"
SIGNATURE = "ab" * 64


class ProvenanceTests(unittest.TestCase):
    def setUp(self):
        # BSAG attaches process-global Loguru sinks to each runner instance.
        logger.remove()
        self.addCleanup(logger.remove)
        # Keep fixture writes inside the editable repository, including on Windows.
        self.temp = tempfile.TemporaryDirectory(dir=PACKAGE)
        self.addCleanup(self.temp.cleanup)
        self.directory = Path(self.temp.name).resolve()
        self.root = self.directory / "submission" / "proj0"
        self.root.mkdir(parents=True)
        self.manifest = self.directory / "provenance-manifest"
        self.manifest.write_text(json.dumps({"assignment_id": "proj0", "sig": SIGNATURE}), encoding="utf-8")
        self.config = ProvenanceConfig(
            assignment_id="proj0",
            expected_manifest=self.manifest,
            assignment_root=self.root,
        )

    def scope(self, relative=".provenance"):
        path = self.root / relative
        path.mkdir(parents=True)
        return path

    def io(self):
        io = Mock()
        io.data = {RESULTS_KEY: Results(score=75)}
        io.step_logs = []
        return io

    def test_empty_selection_never_claims_verification(self):
        self.assertEqual(set(CHECKS), {"invalid_structure", "missing_files", "unexpected_file"})
        self.scope()
        report = verify_assignment(self.root, "proj0", SIGNATURE)
        self.assertEqual(report.outcome, "not_evaluated")
        self.assertEqual(report.scopes, (".provenance",))
        self.assertEqual(report.flags, ())
        io = self.io()
        self.assertTrue(Provenance.run(io, self.config))
        io.student.success.assert_not_called()
        self.assertIn("not enabled", io.student.info.call_args.args[0])
        self.assertEqual(io.data[RESULTS_KEY].score, 75)
        self.assertEqual(io.data[RESULTS_KEY].stdout_visibility, "hidden")

    def test_no_absence_flag_when_no_checks_selected(self):
        report = verify_assignment(self.root, "proj0", SIGNATURE)
        self.assertEqual(report.scopes, ())
        self.assertEqual(report.flags, ())
        self.assertEqual(report.outcome, "not_evaluated")

    def test_only_assignment_root_recording_is_used(self):
        for name in (".provenance", "nested/.provenance", ".git/ignored/.provenance"):
            self.scope(name)
        (self.root.parent / ".provenance").mkdir()
        (self.root.parent / "hw02" / ".provenance").mkdir(parents=True)
        with patch("os.scandir", side_effect=AssertionError("Must not walk the submission")):
            report = verify_assignment(self.root, "proj0", SIGNATURE)
        self.assertEqual(report.scopes, (".provenance",))

    def test_no_fallback_to_other_recordings(self):
        self.scope("nested/.provenance")
        (self.root.parent / ".provenance").mkdir()
        report = verify_assignment(self.root, "proj0", SIGNATURE)
        self.assertEqual(report.scopes, ())
        self.assertEqual(report.outcome, "not_evaluated")

    def test_lookup_does_not_parse_or_flag_student_content(self):
        scope = self.scope()
        (scope / "manifest.json").write_bytes(b"not JSON")
        (scope / "session-fake.slog").write_bytes(b"broken log")
        (scope / "unexpected.txt").write_bytes(b"anything")
        report = verify_assignment(self.root, "proj0", SIGNATURE)
        self.assertEqual(report.outcome, "not_evaluated")
        self.assertEqual(report.flags, ())

    def test_non_directory_recording_path_is_unavailable(self):
        (self.root / ".provenance").write_text("not a directory")
        self.assertEqual(verify_assignment(self.root, "proj0", SIGNATURE).outcome, "error")

    def test_raw_bytes_preserved_and_repeated_reads_allowed(self):
        path = self.scope() / "log.slog"
        payload = b'{"x":1}\r\n{"x":2}\n'
        path.write_bytes(payload)
        reader = SubmissionReader(self.root, max_file_bytes=len(payload))
        for _ in range(10):
            self.assertEqual(reader.read_bytes(path), payload)
        with self.assertRaises(VerificationUnavailable):
            SubmissionReader(self.root, max_file_bytes=len(payload) - 1).read_bytes(path)

    def test_file_size_cap_enforced_even_if_stat_underreports(self):
        path = self.scope() / "log.slog"
        path.write_bytes(b"12345")
        reader = SubmissionReader(self.root, max_file_bytes=4)
        info = Mock(st_mode=path.stat().st_mode, st_size=0, st_file_attributes=0)
        with patch.object(Path, "lstat", return_value=info), self.assertRaises(VerificationUnavailable):
            reader.read_bytes(path)

    def test_invalid_file_size_limit(self):
        for value in (0, -1, True, 1.5):
            with self.subTest(value=value), self.assertRaises(ValueError):
                SubmissionReader(self.root, max_file_bytes=value)

    def test_escape_and_directory_reads_refused(self):
        reader = SubmissionReader(self.root)
        for path in (self.manifest, Path("../provenance-manifest"), self.root):
            with self.subTest(path=path), self.assertRaises(VerificationUnavailable):
                reader.read_bytes(path)

    def test_symlink_is_not_followed(self):
        link = self.root / ".provenance"
        try:
            link.symlink_to(self.manifest)
        except OSError as exc:
            self.skipTest(f"Host does not permit symlinks: {exc}")
        reader = SubmissionReader(self.root)
        with self.assertRaises(VerificationUnavailable):
            reader.read_bytes(link)
        with self.assertRaises(VerificationUnavailable):
            reader.recording_directory()

    @unittest.skipUnless(os.name == "nt", "Junctions are a Windows file type")
    def test_windows_junction_is_not_followed(self):
        target = self.directory / "outside"
        target.mkdir()
        (target / "data").write_bytes(b"outside")
        link = self.root / ".provenance"
        quote = lambda path: "'" + str(path).replace("'", "''") + "'"
        result = subprocess.run(
            [
                "powershell.exe",
                "-NoProfile",
                "-NonInteractive",
                "-Command",
                f"New-Item -ItemType Junction -Path {quote(link)} -Target {quote(target)} | Out-Null",
            ],
            capture_output=True,
            text=True,
            timeout=30,
            check=False,
        )
        self.assertEqual(result.returncode, 0, result.stderr)
        self.addCleanup(link.rmdir)
        reader = SubmissionReader(self.root)
        with self.assertRaises(VerificationUnavailable):
            reader.read_bytes(link / "data")
        with self.assertRaises(VerificationUnavailable):
            reader.recording_directory()
        with self.assertRaises(VerificationUnavailable):
            SubmissionReader(link)

    @unittest.skipUnless(hasattr(os, "mkfifo"), "FIFO is a POSIX file type")
    def test_fifo_is_not_opened(self):
        path = self.root / "pipe"
        os.mkfifo(path)
        with self.assertRaises(VerificationUnavailable):
            SubmissionReader(self.root).read_bytes(path)

    def test_synthetic_checks_receive_context_and_preserve_findings_on_error(self):
        self.scope()

        def flagged(context):
            self.assertEqual(context.expected_sig, SIGNATURE)
            self.assertEqual(context.assignment_id, "proj0")
            self.assertEqual(context.scopes, (self.root / ".provenance",))
            return CheckResult("fake", "flagged", findings=(Finding("fake", "test evidence"),))

        def broken(_context):
            msg = "test checker failure"
            raise RuntimeError(msg)

        report = verify_assignment(
            self.root,
            "proj0",
            SIGNATURE,
            checks=["fake", "broken"],
            registry={"fake": flagged, "broken": broken},
        )
        self.assertEqual(report.outcome, "flagged")
        self.assertEqual(report.checks[1].outcome, "error")
        self.assertEqual(len(report.flags), 1)

    def test_unknown_duplicate_misidentified_and_skipped_checks(self):
        callback = lambda _ctx: CheckResult("fake", "not_evaluated", "No applicable data")
        registry = {"fake": callback}
        for checks in (["unknown"], ["fake", "fake"]):
            with self.subTest(checks=checks), self.assertRaises(VerificationUnavailable):
                verify_assignment(self.root, "proj0", SIGNATURE, checks=checks, registry=registry)
        report = verify_assignment(self.root, "proj0", SIGNATURE, checks=["fake"], registry=registry)
        self.assertEqual(report.outcome, "not_evaluated")
        report = verify_assignment(self.root, "proj0", SIGNATURE, checks=["other"], registry={"other": callback})
        self.assertEqual(report.outcome, "error")

    def test_invalid_check_result_contract(self):
        with self.assertRaises(ValueError):
            CheckResult("fake", "flagged")
        with self.assertRaises(ValueError):
            CheckResult("fake", "passed", findings=(Finding("fake", "bad"),))

    def test_trusted_manifest_failures_are_inside_fail_open(self):
        for content in (b"not json", b"{}", json.dumps({"assignment_id": "wrong", "sig": SIGNATURE}).encode()):
            self.manifest.write_bytes(content)
            io = self.io()
            self.assertTrue(Provenance.run(io, self.config))
            self.assertEqual(io.data[PROVENANCE_REPORT_KEY].outcome, "error")
            io.student.success.assert_not_called()
            io.student.info.assert_called_once()
        self.manifest.unlink()
        # Missing paths must not be rejected during BSAG config construction.
        config = ProvenanceConfig(**self.config.dict())
        io = self.io()
        self.assertTrue(Provenance.run(io, config))
        self.assertEqual(io.data[PROVENANCE_REPORT_KEY].outcome, "error")

    def test_untrusted_expected_manifest_refused(self):
        path = self.root / "manifest"
        path.write_bytes(self.manifest.read_bytes())
        io = self.io()
        config = self.config.copy(update={"expected_manifest": path})
        self.assertTrue(Provenance.run(io, config))
        self.assertEqual(io.data[PROVENANCE_REPORT_KEY].outcome, "error")

    def test_all_adapter_outcomes_and_student_privacy(self):
        cases = [
            (Report(checks=(CheckResult("fake", "passed"),)), True, True),
            (Report(checks=(CheckResult("fake", "not_evaluated", "private detail"),)), True, False),
            (
                Report(checks=(CheckResult("fake", "flagged", findings=(Finding("fake", "private detail"),)),)),
                False,
                False,
            ),
            (Report(errors=("private detail",)), True, False),
        ]
        for report, expected_return, success in cases:
            with self.subTest(outcome=report.outcome):
                io = self.io()
                with patch("bsag_jh61b.provenance.verify_assignment", return_value=report):
                    self.assertEqual(Provenance.run(io, self.config.copy(update={"checks": ["fake"]})), expected_return)
                self.assertEqual(io.student.success.called, success)
                self.assertNotIn("private detail", str(io.student.mock_calls))
                self.assertEqual(len(io.student.mock_calls), 1)
                self.assertEqual(io.data[RESULTS_KEY].score, 75)

    def test_checker_exception_defaults_to_fail_open(self):
        io = self.io()
        with patch("bsag_jh61b.provenance.verify_assignment", side_effect=RuntimeError("test")):
            self.assertTrue(Provenance.run(io, self.config))
            self.assertFalse(Provenance.run(io, self.config.copy(update={"fail_open": False})))
        self.assertTrue(self.config.halt_on_fail)

    def test_real_result_writer_keeps_row_and_hides_stdout(self):
        io = BSAGIO()
        io.data[RESULTS_KEY] = Results(score=75)
        io.step_logs.append(StepLogs(name=Provenance.name(), display_name=Provenance.display_name(self.config)))
        io.step_logs[-1].success = Provenance.run(io, self.config)
        output = self.directory / "results.json"
        WriteResults.run(io, ResultsConfig(output_path=output))
        result = json.loads(output.read_text())
        self.assertEqual(result["score"], 75)
        self.assertEqual(result["stdout_visibility"], "hidden")
        self.assertEqual(result["tests"][0]["name"], "Provenance integrity")
        self.assertIn("not enabled", result["tests"][0]["output"])

    def test_zero_penalty_preserves_final_score_even_on_flag(self):
        io = self.io()
        io.data[TEST_RESULTS_KEY] = {"piece": Jh61bResults(score=3, max_score=4, tests=[])}
        io.step_logs = [StepLogs(name=Provenance.name(), display_name="Provenance integrity", success=False)]
        FinalScore.run(io, FinalScoreConfig(max_points=100, scoring={"piece": 1}, penalties={Provenance.name(): 0.0}))
        self.assertEqual(io.data[RESULTS_KEY].score, 75)

    def test_real_plugin_entrypoint_discovery_and_dry_run(self):
        names = [step.name() for group in get_plugin_manager().hook.bsag_load_step_defs() for step in group]
        self.assertEqual(names.count("jh61b.provenance"), 1)
        config_path = self.directory / "smoke.yaml"
        config_path.write_text(
            yaml.safe_dump(
                {
                    "execution_plan": [
                        {
                            "jh61b.provenance": {
                                "assignment_id": "proj0",
                                "assignment_root": str(self.root),
                                "expected_manifest": str(self.manifest),
                            }
                        }
                    ]
                }
            )
        )
        result = subprocess.run(
            [sys.executable, "-m", "bsag", "--config", str(config_path), "--dry-run"],
            capture_output=True,
            text=True,
            timeout=30,
            check=False,
        )
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)

    def run_report(self, report):
        class Seed(BaseStepDefinition[BaseStepConfig]):
            @staticmethod
            def name():
                return "test.seed"

            @classmethod
            def run(cls, io, config):
                io.data[RESULTS_KEY] = Results(score=75)
                return True

        output = self.directory / "results.json"
        path = self.directory / "runner.yaml"
        path.write_text(
            yaml.safe_dump(
                {
                    "execution_plan": [
                        "test.seed",
                        {
                            "jh61b.provenance": {
                                "assignment_id": "proj0",
                                "assignment_root": str(self.root),
                                "expected_manifest": str(self.manifest),
                            }
                        },
                        {"common.display_message": {"title": "Continued", "text": "Ordinary tests still run"}},
                    ],
                    "teardown_plan": [{"gradescope.results": {"output_path": str(output)}}],
                }
            )
        )
        grader = BSAG(str(path), step_defs=[Seed])
        with patch("bsag_jh61b.provenance.verify_assignment", return_value=report):
            grader.run()
        result = json.loads(output.read_text())
        self.assertEqual(result["score"], 75)
        self.assertEqual(result["stdout_visibility"], "hidden")
        self.assertNotIn("private detail", output.read_text())
        return result

    def test_real_runner_halts_after_synthetic_flag(self):
        report = Report(checks=(CheckResult("fake", "flagged", findings=(Finding("fake", "private detail"),)),))
        result = self.run_report(report)
        self.assertEqual([test["name"] for test in result["tests"]], ["Provenance integrity"])
        self.assertEqual(result["tests"][0]["status"], "failed")
        self.assertIn("grading has stopped", result["tests"][0]["output"])

    def test_real_runner_continues_after_checker_error(self):
        result = self.run_report(Report(errors=("private detail",)))
        self.assertEqual([test["name"] for test in result["tests"]], ["Provenance integrity", "Continued"])
        self.assertEqual(result["tests"][0]["status"], "passed")
        self.assertIn("unavailable", result["tests"][0]["output"])
        self.assertIn("grading continues", result["tests"][0]["output"])

    @unittest.skipUnless(COURSE.is_dir(), "Sibling course-materials checkout not available")
    def test_existing_assignments_do_not_opt_in(self):
        global_config = yaml.safe_load((COURSE / "autograder/global_config.yaml").read_text())
        defaults = global_config["global_settings"]["jh61b.provenance"]
        self.assertEqual(defaults["checks"], [])
        self.assertTrue(defaults["halt_on_fail"])
        for relative in ("proj/proj0", "proj/proj0_hardmode", "hw/hw02", "hw/hw03"):
            with self.subTest(assignment=relative):
                data = yaml.safe_load((COURSE / relative / "grader/config.yaml").read_text())
                plan = data["execution_plan"]
                self.assertFalse(any(isinstance(step, dict) and "jh61b.provenance" in step for step in plan))
                gate = next(
                    step["common.run_command"]
                    for step in plan
                    if isinstance(step, dict) and "common.run_command" in step
                )
                self.assertTrue(gate["halt_on_fail"])
                self.assertIn("exit 1", gate["command"])
                final = next(
                    step["jh61b.final_score"] for step in plan if isinstance(step, dict) and "jh61b.final_score" in step
                )
                self.assertNotIn("jh61b.provenance", final.get("penalties", {}))

    @unittest.skipUnless(COURSE.is_dir(), "Sibling course-materials checkout not available")
    def test_qa_config_resolves_real_steps(self):
        data = yaml.safe_load((COURSE / "hw/hw99/grader/config.yaml").read_text())
        # BSAG's existing sub_info uses FilePath at config load time.
        metadata = self.directory / "metadata.json"
        metadata.write_text("{}")
        data["execution_plan"][0] = {"gradescope.sub_info": {"submission_metatada_path": str(metadata)}}
        path = self.directory / "qa.yaml"
        path.write_text(yaml.safe_dump(data))
        grader = BSAG(str(path), str(COURSE / "autograder/global_config.yaml"))
        self.assertEqual(grader.config.execution_plan[1].config.checks, list(CHECKS))
        self.assertTrue(grader.config.execution_plan[1].config.halt_on_fail)
        self.assertEqual(
            [step.name() for step in grader.config.execution_plan],
            [
                "gradescope.sub_info",
                "jh61b.provenance",
                "common.display_message",
            ],
        )


if __name__ == "__main__":
    unittest.main()
