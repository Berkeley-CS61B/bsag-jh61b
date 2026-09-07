from __future__ import annotations

import json
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import TYPE_CHECKING, Any, NoReturn, TypeGuard

import rfc8785

if TYPE_CHECKING:
    from .types import VerificationContext


def reject(message: str) -> NoReturn:
    raise ValueError(message)


def require(condition: bool, message: str) -> None:
    if not condition:
        reject(message)


def hex_string(value: object, length: int) -> TypeGuard[str]:
    return isinstance(value, str) and re.fullmatch(f"[0-9a-f]{{{length}}}", value) is not None


def string(value: Any) -> bool:
    return isinstance(value, str) and bool(value)


def integer(value: Any) -> bool:
    return type(value) in (int, float) and value >= 0 and value == int(value)


def _integer_token(token: str) -> int | float:
    value = int(token)
    return value if abs(value) <= 2**53 - 1 else float(token)


def _pairs(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result = {}
    for key, value in pairs:
        require(key not in result, "Duplicate JSON key")
        result[key] = value
    return result


def parse_json(raw: bytes) -> dict[str, Any]:
    value = json.loads(raw.decode("utf-8"), object_pairs_hook=_pairs, parse_int=_integer_token)
    require(isinstance(value, dict), "Expected a JSON object")
    rfc8785.dumps(value)
    return value


MANIFEST_FIELDS = (
    "format_version",
    "course_id",
    "assignment_id",
    "semester",
    "issued_at",
    "files_under_review",
    "ignore",
    "attachments",
    "collaboration",
    "submission",
    "scope",
    "policy",
)
CERT_FIELDS = ("course_id", "course_pubkey", "valid_from", "valid_until")


def manifest_shape(value: Any) -> None:
    require(isinstance(value, dict), "Missing activation manifest")
    require(value.get("format_version") == "2.0", "Expected Manifest 2.0 for this grader")
    for key in ("course_id", "assignment_id", "semester", "issued_at"):
        require(string(value.get(key)), f"Missing manifest {key}")
    for key in ("files_under_review", "ignore", "attachments"):
        require(
            isinstance(value.get(key), list) and all(isinstance(x, str) for x in value[key]), f"Invalid manifest {key}"
        )
    for key, allowed in (
        ("collaboration", ("solo", "group")),
        ("submission", ("bundle", "git")),
        ("scope", ("directory", "repo")),
    ):
        require(value.get(key) in allowed, f"Invalid manifest {key}")
    require(isinstance(value.get("policy"), dict), "Missing manifest policy")
    require(hex_string(value.get("sig"), 128), "Invalid manifest signature encoding")
    cert = value.get("course_cert")
    if not isinstance(cert, dict):
        reject("Missing course certificate")
    for key in CERT_FIELDS:
        require(string(cert.get(key)), f"Missing course certificate {key}")
    require(
        hex_string(cert["course_pubkey"], 64) and hex_string(cert.get("root_sig"), 128),
        "Invalid course certificate key/signature encoding",
    )


def meta_shape(value: dict[str, Any]) -> None:
    require(value.get("format_version") == "1.0", "Unsupported metadata version")
    require(
        string(value.get("session_id")) and hex_string(value.get("session_pubkey"), 64), "Invalid metadata session/key"
    )
    encrypted = value.get("encrypted_session_privkey")
    if not isinstance(encrypted, dict):
        reject("Missing encrypted session key")
    require(encrypted.get("algorithm") == "xchacha20-poly1305-hkdf-sha256-v1", "Unsupported key encryption")
    for key in ("nonce", "ciphertext", "salt"):
        require(
            string(encrypted.get(key)) and re.fullmatch("[0-9a-f]+", encrypted[key]) is not None,
            f"Invalid encrypted key {key}",
        )
    require(string(encrypted.get("info")), "Missing encrypted key info")
    require(isinstance(value.get("checkpoints"), list), "Missing checkpoints array")
    for cp in value["checkpoints"]:
        require(
            isinstance(cp, dict)
            and integer(cp.get("seq"))
            and hex_string(cp.get("hash"), 64)
            and hex_string(cp.get("sig"), 128),
            "Invalid checkpoint",
        )


def seal_shape(value: dict[str, Any], rolling: bool) -> None:
    versions = ("1.2",) if rolling else ("1.0", "1.1")
    require(value.get("format_version") in versions, "Unsupported seal version")
    require(string(value.get("assignment_id")) and string(value.get("semester")), "Missing seal assignment")
    require(hex_string(value.get("extension_hash"), 64), "Invalid extension hash")
    sessions = value.get("sessions")
    if not isinstance(sessions, list) or not sessions:
        reject("Missing seal sessions")
    require(not rolling or len(sessions) == 1, "Rolling seal must cover exactly one session")
    require("final" not in value or type(value["final"]) is bool, "Invalid final marker")
    for entry in sessions:
        require(isinstance(entry, dict), "Invalid seal session entry")
        require(
            string(entry.get("session_id")) or (not rolling and entry.get("session_id") is None),
            "Invalid seal session ID",
        )
        require(
            "prev_session_id" in entry and (entry["prev_session_id"] is None or string(entry["prev_session_id"])),
            "Invalid predecessor ID",
        )
        require(
            hex_string(entry.get("slog_sha256"), 64) and hex_string(entry.get("meta_sha256"), 64),
            "Invalid seal digests",
        )
    if value["format_version"] != "1.0":
        require(isinstance(value.get("submission_files"), list), "Missing submission_files")
        for entry in value["submission_files"]:
            require(isinstance(entry, dict) and string(entry.get("path")), "Invalid submission file entry")
            require(
                (entry.get("status") == "present" and hex_string(entry.get("sha256"), 64))
                or (entry.get("status") == "missing" and "sha256" in entry and entry["sha256"] is None),
                "Invalid submission file digest",
            )


def event_shape(value: dict[str, Any]) -> None:
    require(integer(value.get("seq")), "Invalid event sequence")
    require(type(value.get("t")) in (int, float) and isinstance(value.get("wall"), str), "Invalid event times")
    require(string(value.get("kind")) and isinstance(value.get("data"), dict), "Invalid event envelope")
    require(hex_string(value.get("hash"), 64) and hex_string(value.get("prev_hash"), 64), "Invalid event hashes")
    if value["kind"] == "session.start":
        data = value["data"]
        require(data.get("format_version") in ("1.0", "2.0"), "Unsupported session.start version")
        require(string(data.get("session_id")) and hex_string(data.get("session_pubkey"), 64), "Invalid session/key")
        require(
            "prev_session_id" in data and (data["prev_session_id"] is None or string(data["prev_session_id"])),
            "Invalid session predecessor",
        )
        require(hex_string(data.get("manifest_sig"), 128), "Invalid session manifest signature")
        assignment = data.get("assignment")
        require(
            isinstance(assignment, dict) and string(assignment.get("id")) and string(assignment.get("semester")),
            "Invalid session assignment",
        )
        manifest_shape(data.get("manifest"))


@dataclass
class Session:
    name: str
    raw: bytes
    events: list[dict[str, Any]]
    meta: dict[str, Any]
    meta_raw: bytes

    @property
    def start(self) -> dict[str, Any]:
        return self.events[0]["data"]

    @property
    def id(self) -> str:
        return self.start["session_id"] if self.events else self.meta["session_id"]

    @property
    def public_key(self) -> str:
        return self.start["session_pubkey"] if self.events else self.meta["session_pubkey"]


@dataclass
class Seal:
    name: str
    value: dict[str, Any]
    signature: str
    rolling_id: str | None


@dataclass
class Content:
    manifest: dict[str, Any] | None = None
    sessions: list[Session] = field(default_factory=list)
    incomplete_sessions: list[Session] = field(default_factory=list)
    seals: list[Seal] = field(default_factory=list)
    issues: list[tuple[str, str]] = field(default_factory=list)
    notes: list[str] = field(default_factory=list)
    incomplete: bool = False
    unavailable_session_ids: set[str] = field(default_factory=set)

    @property
    def sessions_with_metadata(self) -> list[Session]:
        return self.sessions + self.incomplete_sessions


def load_content(context: VerificationContext) -> Content:
    result = Content()
    structure = context.structure

    def read(name):
        return context.reader.read_bytes(Path(name))

    def attempt(name, operation):
        try:
            return operation()
        except (ValueError, UnicodeError, RecursionError) as exc:
            result.issues.append((name, str(exc)[:300]))
            return None

    def activation():
        value = parse_json(read("provenance-manifest"))
        manifest_shape(value)
        return value

    if structure.manifest_kind == "file":
        result.manifest = attempt("provenance-manifest", activation)
    else:
        result.incomplete = True
    entries = structure.entries
    for name, kind in sorted(entries.items()):
        if kind != "file":
            continue
        if re.fullmatch(r"session-[0-9a-f-]+\.slog", name):
            if entries.get(name + ".meta") != "file":
                result.incomplete = True
                continue

            def session(name=name):
                raw = read(".provenance/" + name)
                meta_raw = read(".provenance/" + name + ".meta")
                meta = parse_json(meta_raw)
                meta_shape(meta)
                result.unavailable_session_ids.add(meta["session_id"])
                events = []
                lines = raw.split(b"\n")
                for index, line in enumerate(lines):
                    if index == len(lines) - 1 and not line:
                        break
                    try:
                        event = parse_json(line)
                    except (ValueError, UnicodeError):
                        if index == len(lines) - 1:
                            result.notes.append(f"{name}: unfinished final log line")
                            result.incomplete = True
                            break
                        raise
                    event_shape(event)
                    events.append(event)
                if not events:
                    result.notes.append(f"{name}: no complete events")
                    result.incomplete = True
                    result.incomplete_sessions.append(Session(name, raw, [], meta, meta_raw))
                    return None
                require(events[0]["kind"] == "session.start", "First event is not session.start")
                require(sum(e["kind"] == "session.start" for e in events) == 1, "Repeated session.start")
                return Session(name, raw, events, meta, meta_raw)

            parsed = attempt(name, session)
            if parsed is not None:
                result.sessions.append(parsed)
                result.unavailable_session_ids.discard(parsed.meta["session_id"])
        match = re.fullmatch(r"manifest-([0-9a-f-]+)\.json", name)
        if name == "manifest.json" or match:
            sig_name = name[:-5] + ".sig"
            if entries.get(sig_name) != "file":
                result.incomplete = True
                continue

            def seal(name=name, sig_name=sig_name, match=match):
                value = parse_json(read(".provenance/" + name))
                seal_shape(value, bool(match))
                signature = read(".provenance/" + sig_name).decode("ascii").strip()
                require(hex_string(signature, 128), "Invalid seal signature encoding")
                return Seal(name, value, signature, match[1] if match else None)

            parsed = attempt(name, seal)
            if parsed is not None:
                result.seals.append(parsed)
    if not result.sessions or not result.seals:
        result.incomplete = True
    return result
