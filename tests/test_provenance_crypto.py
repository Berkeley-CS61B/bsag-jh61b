"""Real Ed25519 fixtures exercise mutations and recorder crash/growth semantics."""

import copy
import json
import tempfile
import unittest
from hashlib import sha256
from pathlib import Path
from unittest.mock import Mock, patch

import rfc8785
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from bsag_jh61b.provenance.content import MANIFEST_FIELDS, parse_json
from bsag_jh61b.provenance.crypto import verifies
from bsag_jh61b.provenance.step import PROVENANCE_REPORT_KEY, Provenance, ProvenanceConfig
from bsag_jh61b.provenance.verify import CHECKS, verify_assignment

PACKAGE = Path(__file__).resolve().parents[1]


def public(key):
    return key.public_key().public_bytes_raw().hex()


def sign(key, value):
    return key.sign(rfc8785.dumps(value)).hex()


def chain(events):
    previous = "0" * 64
    for event in events:
        payload = {k: v for k, v in event.items() if k not in ("hash", "prev_hash")}
        event["prev_hash"] = previous
        event["hash"] = sha256(previous.encode() + rfc8785.dumps(payload)).hexdigest()
        previous = event["hash"]


class CryptoTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(dir=PACKAGE)
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.recording = self.root / ".provenance"
        self.recording.mkdir()
        self.root_key, self.course_key, self.session_key = (Ed25519PrivateKey.generate() for _ in range(3))
        cert = {
            "course_id": "course",
            "course_pubkey": public(self.course_key),
            "valid_from": "2026-01-01",
            "valid_until": "2027-01-01",
        }
        cert["root_sig"] = sign(self.root_key, cert)
        self.manifest = {
            "format_version": "2.0",
            "course_id": "course",
            "assignment_id": "hw99",
            "semester": "fa26",
            "issued_at": "2026-09-01T00:00:00Z",
            "files_under_review": ["src/"],
            "ignore": [],
            "attachments": [],
            "collaboration": "solo",
            "submission": "git",
            "scope": "directory",
            "policy": {},
            "course_cert": cert,
        }
        self.manifest["sig"] = sign(self.course_key, {k: self.manifest[k] for k in MANIFEST_FIELDS})
        self.expected = copy.deepcopy(self.manifest)
        self.session_id = "aaaa-bbbb"
        self.log_name = "session-1111-2222.slog"
        self.seal_name = "manifest-aaaa-bbbb.json"
        self.events = [
            {
                "seq": 0,
                "t": 0,
                "wall": "2026-09-01T00:00:00Z",
                "kind": "session.start",
                "data": {
                    "format_version": "1.0",
                    "session_id": self.session_id,
                    "prev_session_id": None,
                    "assignment": {"id": "hw99", "semester": "fa26"},
                    "session_pubkey": public(self.session_key),
                    "manifest_sig": self.manifest["sig"],
                    "manifest": copy.deepcopy(self.manifest),
                },
            },
            {
                "seq": 1,
                "t": 1.5,
                "wall": "2026-09-01T00:00:01Z",
                "kind": "session.heartbeat",
                "data": {"focused": True},
            },
            {"seq": 2, "t": 2, "wall": "2026-09-01T00:00:02Z", "kind": "session.end", "data": {"reason": "test"}},
        ]
        chain(self.events)
        self.meta = {
            "format_version": "1.0",
            "session_id": self.session_id,
            "session_pubkey": public(self.session_key),
            "encrypted_session_privkey": {
                "algorithm": "xchacha20-poly1305-hkdf-sha256-v1",
                "nonce": "11" * 24,
                "ciphertext": "22" * 48,
                "salt": "33" * 32,
                "info": "provenance/session",
            },
            "checkpoints": [],
        }
        self.checkpoint(1)
        self.write()
        self.seal = {
            "format_version": "1.2",
            "assignment_id": "hw99",
            "semester": "fa26",
            "extension_hash": "00" * 32,
            "sessions": [
                {
                    "session_id": self.session_id,
                    "prev_session_id": None,
                    "slog_sha256": sha256(self.raw()).hexdigest(),
                    "meta_sha256": sha256(rfc8785.dumps(self.meta)).hexdigest(),
                }
            ],
            "submission_files": [],
        }
        self.write_seal()

    def raw(self):
        return b"".join(rfc8785.dumps(e) + b"\n" for e in self.events)

    def write(self):
        (self.root / "provenance-manifest").write_bytes(rfc8785.dumps(self.manifest))
        (self.recording / self.log_name).write_bytes(self.raw())
        (self.recording / (self.log_name + ".meta")).write_bytes(rfc8785.dumps(self.meta))

    def write_seal(self, name=None, value=None, key=None):
        name, value, key = name or self.seal_name, value or self.seal, key or self.session_key
        (self.recording / name).write_bytes(rfc8785.dumps(value))
        (self.recording / (name[:-5] + ".sig")).write_text(sign(key, value), encoding="ascii")

    def checkpoint(self, seq, digest=None):
        cp = {"seq": seq, "hash": digest or self.events[seq]["hash"]}
        cp["sig"] = sign(self.session_key, cp)
        self.meta["checkpoints"].append(cp)

    def report(self, checks=tuple(CHECKS), **kwargs):
        return verify_assignment(
            self.root,
            "hw99",
            self.expected,
            checks=checks,
            root_public_key=kwargs.get("root_public_key", public(self.root_key)),
        )

    def flag(self, name):
        report = self.report()
        self.assertIn(name, [f.check for f in report.flags], report)
        self.assertFalse(report.errors, report)
        self.assertFalse(any(c.outcome == "error" for c in report.checks), report)

    def test_honest_recording_with_different_filename_id_passes(self):
        self.assertEqual(self.report().outcome, "passed", self.report())

    def test_content_edit_breaks_chain_and_bytes(self):
        self.events[1]["data"]["focused"] = False
        self.write()
        self.flag("hash_chain_invalid")
        self.flag("log_bytes_mismatch")

    def test_deleted_middle_event_detected_even_with_intact_self_hashes(self):
        self.events.pop(1)
        self.write()
        self.flag("hash_chain_invalid")

    def test_rehashed_log_still_contradicts_seal(self):
        self.events[1]["data"]["focused"] = False
        chain(self.events)
        self.write()
        report = self.report()
        self.assertNotIn("hash_chain_invalid", [f.check for f in report.flags])
        self.flag("log_bytes_mismatch")

    def test_genesis_and_sequence_checked(self):
        self.events[0]["seq"] = 1
        chain(self.events)
        self.write()
        self.flag("hash_chain_invalid")

    def test_all_signature_layers(self):
        mutations = ("root", "course", "embedded", "rolling", "checkpoint")
        for mutation in mutations:
            with self.subTest(mutation=mutation):
                self.setUp()
                if mutation == "root":
                    self.manifest["course_cert"]["root_sig"] = "00" * 64
                elif mutation == "course":
                    self.manifest["policy"] = {"changed": True}
                elif mutation == "embedded":
                    self.events[0]["data"]["manifest"]["policy"] = {"changed": True}
                elif mutation == "checkpoint":
                    self.meta["checkpoints"][0]["sig"] = "00" * 64
                else:
                    self.write_seal(key=Ed25519PrivateKey.generate())
                self.write()
                self.flag("invalid_signature")

    def test_wrong_course_assignment_and_semester(self):
        for key in ("course_id", "assignment_id", "semester"):
            with self.subTest(key=key):
                self.expected[key] += "wrong"
                self.flag("recording_binding_mismatch")
                self.expected[key] = self.manifest[key]

    def test_manifest_reissue_and_whitespace_do_not_require_exact_signature(self):
        self.manifest["issued_at"] = "2026-09-02T00:00:00Z"
        self.manifest["sig"] = sign(self.course_key, {k: self.manifest[k] for k in MANIFEST_FIELDS})
        (self.root / "provenance-manifest").write_text(json.dumps(self.manifest, indent=2), encoding="utf-8")
        self.assertEqual(self.report().outcome, "passed", self.report())

    def test_meta_key_and_log_id_binding(self):
        self.meta["session_id"] = "cccc"
        self.meta["session_pubkey"] = public(Ed25519PrivateKey.generate())
        self.write()
        self.flag("recording_binding_mismatch")

    def test_rolling_filename_and_session_coverage(self):
        self.seal["sessions"][0]["session_id"] = "cccc"
        self.write_seal()
        self.flag("recording_binding_mismatch")

    def test_duplicate_logical_session(self):
        (self.recording / "session-3333.slog").write_bytes(self.raw())
        (self.recording / "session-3333.slog.meta").write_bytes(rfc8785.dumps(self.meta))
        self.flag("recording_binding_mismatch")
        (self.recording / "session-3333.slog").write_bytes(b"")
        self.flag("recording_binding_mismatch")

    def test_rolling_signature_never_falls_back_to_another_session_key(self):
        other_key = Ed25519PrivateKey.generate()
        other_events = copy.deepcopy(self.events)
        other_events[0]["data"]["session_id"] = "cccc"
        other_events[0]["data"]["session_pubkey"] = public(other_key)
        chain(other_events)
        other_raw = b"".join(rfc8785.dumps(e) + b"\n" for e in other_events)
        other_meta = {**self.meta, "session_id": "cccc", "session_pubkey": public(other_key), "checkpoints": []}
        (self.recording / "session-dddd.slog").write_bytes(other_raw)
        (self.recording / "session-dddd.slog.meta").write_bytes(rfc8785.dumps(other_meta))
        other_seal = copy.deepcopy(self.seal)
        other_seal["sessions"] = [
            {
                "session_id": "cccc",
                "prev_session_id": None,
                "slog_sha256": sha256(other_raw).hexdigest(),
                "meta_sha256": sha256(rfc8785.dumps(other_meta)).hexdigest(),
            }
        ]
        self.write_seal("manifest-cccc.json", other_seal, other_key)
        self.assertEqual(self.report().outcome, "passed", self.report())
        self.write_seal(key=other_key)
        self.flag("invalid_signature")

    def test_removed_whole_log_pair_is_detected_by_seal_reference(self):
        extra = copy.deepcopy(self.seal)
        extra["sessions"][0]["session_id"] = "cccc"
        self.write_seal("manifest-cccc.json", extra)
        self.flag("recording_binding_mismatch")
        # An unrelated interrupted write must not excuse a missing session.
        (self.recording / self.log_name).write_bytes(self.raw() + b'{"seq":3')
        self.flag("recording_binding_mismatch")

    def test_final_metadata_edit_and_checkpoint_removal(self):
        self.seal["final"] = True
        self.write_seal()
        self.meta["checkpoints"] = []
        self.write()
        self.flag("log_bytes_mismatch")

    def test_metadata_whitespace_does_not_reproduce_signed_bytes(self):
        (self.recording / (self.log_name + ".meta")).write_text(json.dumps(self.meta, indent=2), encoding="utf-8")
        self.flag("log_bytes_mismatch")

    def test_zero_checkpoint_short_recording_is_valid(self):
        self.meta["checkpoints"] = []
        self.write()
        self.seal["sessions"][0]["meta_sha256"] = sha256(rfc8785.dumps(self.meta)).hexdigest()
        self.write_seal()
        self.assertEqual(self.report().outcome, "passed", self.report())

    def test_erasing_entire_log_still_checks_signed_bytes_using_metadata_key(self):
        (self.recording / self.log_name).write_bytes(b"")
        self.flag("log_bytes_mismatch")

    def test_honestly_empty_sealed_log_is_incomplete(self):
        (self.recording / self.log_name).write_bytes(b"")
        self.seal["sessions"][0]["slog_sha256"] = sha256(b"").hexdigest()
        self.write_seal()
        report = self.report()
        self.assertEqual(report.outcome, "not_evaluated", report)
        self.assertFalse(report.flags)

    def test_wrong_configured_root_is_an_infrastructure_error(self):
        staff = self.root / "staff-copy"
        staff.write_bytes(rfc8785.dumps(self.expected))
        # Use an independent assignment child so the staff reference is outside submission.
        submission = self.root / "submission"
        submission.mkdir()
        config = ProvenanceConfig(
            assignment_root=submission,
            expected_manifest=staff,
            assignment_id="hw99",
            checks=["invalid_signature"],
            root_public_key=public(Ed25519PrivateKey.generate()),
        )
        io = Mock(data={})
        self.assertTrue(Provenance.run(io, config))
        self.assertEqual(io.data[PROVENANCE_REPORT_KEY].outcome, "error")
        self.assertFalse(io.data[PROVENANCE_REPORT_KEY].flags)

    def test_log_and_metadata_prefixes(self):
        self.events.append({"seq": 3, "t": 3, "wall": "2026-09-01T00:00:03Z", "kind": "session.heartbeat", "data": {}})
        chain(self.events)
        self.checkpoint(3)
        self.write()
        report = self.report()
        self.assertEqual(report.outcome, "passed", report)
        self.assertIn("unsealed tail", report.checks[-1].detail)
        self.assertIn("unsealed checkpoints", report.checks[-1].detail)

    def test_final_seal_rejects_append(self):
        self.seal["final"] = True
        self.write_seal()
        self.events.append({"seq": 3, "t": 3, "wall": "later", "kind": "session.heartbeat", "data": {}})
        chain(self.events)
        self.write()
        self.flag("log_bytes_mismatch")

    def test_crlf_translation_passes_final_and_nonfinal(self):
        for final in (True, False):
            self.seal["final"] = final
            self.write_seal()
            (self.recording / self.log_name).write_bytes(self.raw().replace(b"\n", b"\r\n"))
            self.assertEqual(self.report().outcome, "passed", self.report())

    def test_classic_signature_and_stale_classic_bytes(self):
        classic = {**copy.deepcopy(self.seal), "format_version": "1.1"}
        self.write_seal("manifest.json", classic)
        self.events.append({"seq": 3, "t": 3, "wall": "later", "kind": "session.heartbeat", "data": {}})
        chain(self.events)
        self.checkpoint(3)
        self.write()
        self.seal["sessions"][0]["slog_sha256"] = sha256(self.raw()).hexdigest()
        self.seal["sessions"][0]["meta_sha256"] = sha256(rfc8785.dumps(self.meta)).hexdigest()
        self.seal["final"] = True
        self.write_seal()
        self.assertEqual(self.report().outcome, "passed", self.report())
        self.write_seal("manifest.json", classic, Ed25519PrivateKey.generate())
        self.flag("invalid_signature")

    def test_checkpoint_past_tail_still_requires_valid_signature(self):
        self.checkpoint(100, "ab" * 32)
        self.write()
        report = self.report()
        self.assertEqual(report.outcome, "passed", report)
        self.meta["checkpoints"][-1]["sig"] = "00" * 64
        self.write()
        self.flag("invalid_signature")

    def test_invalid_complete_json_and_shapes_are_findings(self):
        for raw in (b"{}\n", b"garbage\n", b'{"seq":0,"seq":1}\n', b'{"x":NaN}\n'):
            with self.subTest(raw=raw):
                (self.recording / self.log_name).write_bytes(raw)
                self.flag("invalid_content")

    def test_torn_final_line_is_incomplete_without_tampering_flag(self):
        (self.recording / self.log_name).write_bytes(self.raw() + b'{"seq":3')
        report = self.report()
        self.assertEqual(report.outcome, "not_evaluated", report)
        self.assertFalse(report.flags)

    def test_missing_root_is_operational_error(self):
        report = self.report(checks=["invalid_signature"], root_public_key=None)
        self.assertEqual(report.outcome, "error", report)
        self.assertFalse(report.flags)

    def test_unverified_seal_cannot_accuse_bytes(self):
        self.seal["sessions"][0]["slog_sha256"] = "00" * 32
        (self.recording / self.seal_name).write_bytes(rfc8785.dumps(self.seal))
        self.assertEqual(self.report(checks=["log_bytes_mismatch"]).outcome, "not_evaluated")
        self.flag("invalid_signature")

    def test_actual_crypto_finding_halts_adapter(self):
        self.events[1]["data"]["focused"] = False
        self.write()
        io = Mock(data={})
        config = ProvenanceConfig(assignment_root=self.root, assignment_id="hw99", checks=["hash_chain_invalid"])
        self.assertFalse(Provenance.run(io, config))
        self.assertTrue(config.halt_on_fail)
        self.assertEqual(io.data[PROVENANCE_REPORT_KEY].outcome, "flagged")

    def test_structure_selection_never_parses_content_or_reads_staff_manifest(self):
        config = ProvenanceConfig(assignment_root=self.root, assignment_id="hw99", checks=["missing_files"])
        with patch("bsag_jh61b.provenance.content.load_content", side_effect=AssertionError("unexpected parse")):
            self.assertTrue(Provenance.run(Mock(data={}), config))


class CanonicalTests(unittest.TestCase):
    @unittest.skipUnless(
        (PACKAGE.parent / "course-materials-fa26/proj/proj0/skeleton/provenance-manifest").is_file(),
        "Course skeleton is not available",
    )
    def test_existing_course_signature_matches_signed_field_selection(self):
        # Independently issued by the existing tool, not the Python fixture signer.
        manifest = json.loads(
            (PACKAGE.parent / "course-materials-fa26/proj/proj0/skeleton/provenance-manifest").read_text()
        )
        self.assertTrue(
            verifies(
                manifest["course_cert"]["course_pubkey"], manifest["sig"], {k: manifest[k] for k in MANIFEST_FIELDS}
            )
        )

    def test_number_and_unicode_vectors(self):
        raw = b'{"value":100000000000000000000}'
        self.assertEqual(rfc8785.dumps(parse_json(raw)), raw)
        self.assertEqual(rfc8785.dumps(parse_json(b'{"value":9007199254740993}')), b'{"value":9007199254740992}')
        self.assertEqual(
            rfc8785.dumps([1e-7, 1e-6, 1e20, 1e21, -0.0]), b"[1e-7,0.000001,100000000000000000000,1e+21,0]"
        )
        self.assertEqual(rfc8785.dumps({"\ue000": 1, "\U00010000": 2}).decode(), '{"\U00010000":2,"\ue000":1}')

    def test_upstream_pinned_hash_vector(self):
        # log-core/src/hash-chain.test.ts, pinned by the TypeScript implementation.
        envelope = {
            "seq": 0,
            "t": 0,
            "wall": "2026-01-01T00:00:00.000Z",
            "kind": "session.end",
            "data": {"reason": "test"},
        }
        self.assertEqual(
            sha256(b"0" * 64 + rfc8785.dumps(envelope)).hexdigest(),
            "d33cad1d38b90b26a2f7b1181801805233bf4332eca5bc6d4ff4e1b677683625",
        )

    def test_reject_ambiguous_json(self):
        for raw in (b'{"a":1,"a":2}', b'{"a":NaN}', b'{"a":1e400}', b'{"a":"\\ud800"}'):
            with self.subTest(raw=raw), self.assertRaises((ValueError, UnicodeError)):
                parse_json(raw)
