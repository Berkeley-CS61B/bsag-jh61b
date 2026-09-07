import os
import tempfile
import unittest
from pathlib import Path
from unittest.mock import Mock, patch

from bsag.steps.gradescope import RESULTS_KEY, Results

from bsag_jh61b.provenance import PROVENANCE_REPORT_KEY, Provenance, ProvenanceConfig
from bsag_jh61b.provenance_verify import CHECKS, verify_assignment


class StructuralTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory(dir=Path(__file__).resolve().parents[1])
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name).resolve()
        self.recording = self.root / ".provenance"
        self.recording.mkdir()
        (self.root / "provenance-manifest").write_bytes(b"unparsed manifest")
        self.files = (
            "session-aaaaaaaa.slog",
            "session-aaaaaaaa.slog.meta",
            "manifest-bbbbbbbb.json",
            "manifest-bbbbbbbb.sig",
        )
        for name in self.files:
            (self.recording / name).write_bytes(b"")

    def report(self, checks=tuple(CHECKS)):
        return verify_assignment(self.root, "test", "unused", checks=checks)

    def test_complete_structure_without_reading_contents_or_matching_log_and_seal_ids(self):
        with (
            patch.object(Path, "open", side_effect=AssertionError("No content reads")),
            patch("builtins.open", side_effect=AssertionError("No content reads")),
            patch("os.open", side_effect=AssertionError("No content reads")),
            patch("os.scandir", wraps=os.scandir) as scan,
        ):
            report = self.report()
        self.assertEqual(report.outcome, "passed")
        scan.assert_called_once_with(self.recording)

    def test_each_missing_companion(self):
        for name in self.files:
            with self.subTest(name=name):
                path = self.recording / name
                path.unlink()
                report = self.report()
                self.assertEqual({f.check for f in report.flags}, {"missing_files"})
                self.assertTrue(any(name in f.detail for f in report.flags))
                path.touch()

    def test_manifest_and_recording_absence(self):
        (self.root / "provenance-manifest").unlink()
        report = self.report()
        self.assertEqual({f.check for f in report.flags}, {"missing_files"})
        for name in self.files:
            (self.recording / name).unlink()
        self.recording.rmdir()
        report = self.report()
        self.assertEqual(report.outcome, "flagged")
        self.assertEqual(len(report.flags), 2)

    def test_auxiliary_files_do_not_satisfy_required_pairs(self):
        for name in self.files:
            (self.recording / name).unlink()
        for name in (".gitattributes", ".DS_Store"):
            (self.recording / name).touch()
        self.assertEqual({f.check for f in self.report().flags}, {"missing_files"})

    def test_allowed_auxiliary_classic_and_multiple_pairs(self):
        for name in (
            ".gitattributes",
            ".DS_Store",
            "Thumbs.db",
            "desktop.ini",
            "manifest.json",
            "manifest.sig",
            "session-cccccccc.slog",
            "session-cccccccc.slog.meta",
            "manifest-dddddddd.json",
            "manifest-dddddddd.sig",
            "manifest-dddddddd.sig.123.0123456789abcdef.tmp",
            "session-cccccccc.slog.meta.123.0123456789abcdef.tmp",
        ):
            (self.recording / name).touch()
        self.assertEqual(self.report().outcome, "passed")

    def test_optional_classic_pair_must_be_complete_and_does_not_replace_rolling_seals(self):
        (self.recording / "manifest.json").touch()
        self.assertTrue(any("manifest.sig" in f.detail for f in self.report().flags))
        (self.recording / "manifest.sig").touch()
        self.assertEqual(self.report().outcome, "passed")
        for name in self.files[2:]:
            (self.recording / name).unlink()
        self.assertEqual({f.check for f in self.report().flags}, {"missing_files"})

    def test_quarantine_explains_only_its_own_orphaned_sidecar(self):
        (self.recording / "session-eeeeeeee.slog.meta").touch()
        self.assertEqual(self.report().outcome, "flagged")
        quarantine = self.recording / "session-eeeeeeee.slog.corrupt-2026-09-07T01-02-03-004Z"
        quarantine.touch()
        self.assertEqual(self.report().outcome, "passed")
        (self.recording / "session-ffffffff.slog.meta").touch()
        self.assertTrue(any("session-ffffffff.slog" in f.detail for f in self.report().flags))

    def test_unexpected_files_and_malformed_auxiliary_names(self):
        for name in ("extra.txt", "anything.tmp", "manifest-bbbbbbbb.sig.123.bad.tmp", "session-not-an-id.slog"):
            path = self.recording / name
            path.touch()
            with self.subTest(name=name):
                self.assertEqual({f.check for f in self.report().flags}, {"unexpected_file"})
            path.unlink()
        (self.root / "Main.java").touch()
        (self.root / "notes.txt").touch()
        self.assertEqual(self.report().outcome, "passed")

    def test_subdirectory_is_invalid_and_never_traversed(self):
        nested = self.recording / "extra"
        nested.mkdir()
        (nested / "unknown.txt").touch()
        report = self.report()
        self.assertEqual({f.check for f in report.flags}, {"invalid_structure"})
        self.assertNotIn("unknown.txt", str(report))

    def test_invalid_recording_and_assignment_manifest_types(self):
        manifest = self.root / "provenance-manifest"
        manifest.unlink()
        manifest.mkdir()
        self.assertEqual({f.check for f in self.report().flags}, {"invalid_structure"})
        for name in self.files:
            (self.recording / name).unlink()
        self.recording.rmdir()
        self.recording.touch()
        self.assertEqual({f.check for f in self.report().flags}, {"invalid_structure"})

    def test_expected_file_replaced_with_directory(self):
        name = self.files[0]
        (self.recording / name).unlink()
        (self.recording / name).mkdir()
        report = self.report()
        self.assertIn("invalid_structure", {f.check for f in report.flags})

    def test_permission_error_is_not_a_finding(self):
        with patch("os.scandir", side_effect=PermissionError("unreadable")):
            report = self.report()
        self.assertEqual(report.outcome, "error")
        self.assertEqual(report.flags, ())

    def test_selected_detectors_only(self):
        (self.recording / "extra.txt").touch()
        self.assertEqual(self.report(checks=["missing_files"]).outcome, "passed")
        self.assertEqual(self.report(checks=[]).outcome, "not_evaluated")

    def test_actual_structural_finding_returns_failure_from_bsag_step(self):
        (self.recording / "extra.txt").touch()
        io = Mock()
        io.data = {RESULTS_KEY: Results()}
        config = ProvenanceConfig(
            assignment_id="test",
            assignment_root=self.root,
            expected_manifest=self.root.parent / "unused",
            checks=list(CHECKS),
        )
        with patch("bsag_jh61b.provenance._expected_signature", return_value="unused"):
            self.assertFalse(Provenance.run(io, config))
        self.assertTrue(config.halt_on_fail)
        self.assertEqual(io.data[PROVENANCE_REPORT_KEY].outcome, "flagged")
        self.assertNotIn("extra.txt", str(io.student.mock_calls))

    def test_link_types_rejected_without_following(self):
        # Exercise link classification on hosts that cannot create real symlinks.
        actual_lstat = Path.lstat

        def lstat(path, *args, **kwargs):
            if path == self.recording:
                return Mock(st_mode=0o120777, st_file_attributes=0)
            return actual_lstat(path, *args, **kwargs)

        with patch.object(Path, "lstat", lstat), patch("os.scandir", side_effect=AssertionError("Followed a link")):
            self.assertEqual({f.check for f in self.report().flags}, {"invalid_structure"})
