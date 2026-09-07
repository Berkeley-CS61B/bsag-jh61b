from hashlib import sha256

import rfc8785

from .content import Session
from .types import CheckResult, Finding, VerificationContext, VerificationUnavailable


def result(context, name, issues, notes=(), incomplete=False):
    content = context.content
    findings = tuple(Finding(name, detail, scope) for scope, detail in issues)
    detail = "; ".join([*content.notes, *notes])
    if findings:
        return CheckResult(name, "flagged", detail, findings)
    skipped = incomplete or content.incomplete or (bool(content.issues) and name != "invalid_content")
    return CheckResult(name, "not_evaluated" if skipped else "passed", detail)


def invalid_content(context: VerificationContext) -> CheckResult:
    return result(context, "invalid_content", context.content.issues)


def hash_chain_invalid(context: VerificationContext) -> CheckResult:
    issues = []
    for session in context.content.sessions:
        previous = "0" * 64
        sequence = 0
        for event in session.events:
            envelope = {k: v for k, v in event.items() if k not in ("hash", "prev_hash")}
            digest = sha256(event["prev_hash"].encode("ascii") + rfc8785.dumps(envelope)).hexdigest()
            if event["prev_hash"] != previous or event["hash"] != digest or event["seq"] != sequence:
                issues.append((session.name, f"Invalid hash, link, or sequence at seq {event['seq']}"))
            previous = event["hash"]
            sequence = event["seq"] + 1
    return result(context, "hash_chain_invalid", issues)


def invalid_signature(context: VerificationContext) -> CheckResult:
    signatures = context.signatures
    missing = any(seal.name not in signatures.seals for seal in context.content.seals)
    return result(context, "invalid_signature", signatures.failures, incomplete=missing)


def recording_binding_mismatch(context: VerificationContext) -> CheckResult:
    expected = context.expected_manifest
    if not isinstance(expected, dict) or any(not expected.get(k) for k in ("course_id", "semester", "assignment_id")):
        msg = "Trusted assignment course_id, semester and assignment_id are required"
        raise VerificationUnavailable(msg)
    issues = []
    content = context.content

    def binding(name, manifest):
        for key in ("course_id", "semester", "assignment_id"):
            if manifest[key] != expected[key]:
                issues.append((name, f"Manifest {key} differs from the trusted assignment"))
        if manifest["course_id"] != manifest["course_cert"]["course_id"]:
            issues.append((name, "Manifest course differs from its certificate"))

    if content.manifest is not None:
        binding("provenance-manifest", content.manifest)
    ids = [s.id for s in content.sessions_with_metadata]
    rolling_ids = [seal.rolling_id for seal in content.seals if seal.rolling_id is not None]
    for session in content.sessions_with_metadata:
        if ids.count(session.id) != 1:
            issues.append((session.name, "Duplicate logical session ID"))
    for session in content.sessions:
        start = session.start
        binding(session.name, start["manifest"])
        if start["manifest_sig"] != start["manifest"]["sig"]:
            issues.append((session.name, "Session manifest_sig differs from embedded manifest signature"))
        if start["assignment"] != {"id": expected["assignment_id"], "semester": expected["semester"]}:
            issues.append((session.name, "Session assignment differs from the trusted assignment"))
        if session.meta["session_id"] != session.id or session.meta["session_pubkey"] != start["session_pubkey"]:
            issues.append((session.name, "Log and metadata session ID/key disagree"))
        if session.id not in rolling_ids:
            issues.append((session.name, "Session has no corresponding rolling seal"))
    for seal in content.seals:
        value = seal.value
        if value["assignment_id"] != expected["assignment_id"] or value["semester"] != expected["semester"]:
            issues.append((seal.name, "Seal belongs to a different assignment/semester"))
        if seal.rolling_id is not None and value["sessions"][0]["session_id"] != seal.rolling_id:
            issues.append((seal.name, "Rolling seal filename and logical session ID disagree"))
        seen = set()
        for entry in value["sessions"]:
            sid = entry["session_id"]
            if sid is None:
                continue
            matches = [s for s in content.sessions if s.id == sid]
            if len(matches) != 1:
                if sid not in content.unavailable_session_ids:
                    issues.append((seal.name, "Seal references a missing or ambiguous session"))
            elif entry["prev_session_id"] != matches[0].start["prev_session_id"]:
                issues.append((seal.name, "Seal and log predecessor IDs disagree"))
            if sid in seen:
                issues.append((seal.name, "Repeated session in seal"))
            seen.add(sid)
    return result(context, "recording_binding_mismatch", issues)


def _log_coverage(raw: bytes, digest: str, whole: bool) -> str | None:
    for data in (raw, raw.replace(b"\r\n", b"\n")):
        if sha256(data).hexdigest() == digest:
            return "exact" if data == raw else "line endings translated"
        if not whole:
            running = sha256()
            if running.hexdigest() == digest:
                return "unsealed tail"
            for line in data.splitlines(keepends=True):
                running.update(line)
                if line.endswith(b"\n") and running.hexdigest() == digest:
                    return "unsealed tail"
    return None


def _meta_coverage(session: Session, digest: str, whole: bool) -> str | None:
    if sha256(session.meta_raw).hexdigest() == digest:
        return "exact"
    if not whole:
        for count in range(len(session.meta["checkpoints"])):
            prior = {**session.meta, "checkpoints": session.meta["checkpoints"][:count]}
            if sha256(rfc8785.dumps(prior)).hexdigest() == digest:
                return "unsealed checkpoints"
    return None


def log_bytes_mismatch(context: VerificationContext) -> CheckResult:
    issues, notes = [], []
    incomplete = False
    content = context.content
    signatures = context.signatures
    verified_rolling = {s.rolling_id for s in content.seals if s.rolling_id and s.name in signatures.seals}
    for seal in content.seals:
        if seal.name not in signatures.seals:
            incomplete = True
            continue
        for entry in seal.value["sessions"]:
            sid = entry["session_id"]
            matches = [s for s in content.sessions_with_metadata if s.id == sid]
            if len(matches) != 1 or (seal.rolling_id is not None and seal.rolling_id != sid):
                incomplete = True
                continue
            session = matches[0]
            whole = seal.value.get("final") is True if seal.rolling_id else sid not in verified_rolling
            for label, coverage in (
                ("log", _log_coverage(session.raw, entry["slog_sha256"], whole)),
                ("metadata", _meta_coverage(session, entry["meta_sha256"], whole)),
            ):
                if coverage is None:
                    issues.append((seal.name, f"Signed {label} bytes do not match {session.name}"))
                elif coverage != "exact":
                    notes.append(f"{session.name} ({seal.name}): {coverage}")
    return result(context, "log_bytes_mismatch", issues, notes, incomplete)
