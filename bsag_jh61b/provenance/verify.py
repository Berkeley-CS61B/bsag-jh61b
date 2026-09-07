from collections.abc import Mapping, Sequence
from pathlib import Path
from types import MappingProxyType

from .integrity import (
    hash_chain_invalid,
    invalid_content,
    invalid_signature,
    log_bytes_mismatch,
    recording_binding_mismatch,
)
from .io import DEFAULT_MAX_FILE_BYTES, SubmissionReader
from .structure import invalid_structure, missing_files, unexpected_file
from .types import Check, CheckResult, Report, VerificationContext, VerificationUnavailable

CHECKS: Mapping[str, Check] = MappingProxyType(
    {
        "invalid_structure": invalid_structure,
        "missing_files": missing_files,
        "unexpected_file": unexpected_file,
        "invalid_content": invalid_content,
        "hash_chain_invalid": hash_chain_invalid,
        "invalid_signature": invalid_signature,
        "recording_binding_mismatch": recording_binding_mismatch,
        "log_bytes_mismatch": log_bytes_mismatch,
    }
)


def verify_assignment(
    assignment_root: Path,
    assignment_id: str,
    expected_manifest: dict | None = None,
    *,
    checks: Sequence[str] = (),
    max_file_bytes: int = DEFAULT_MAX_FILE_BYTES,
    registry: Mapping[str, Check] | None = None,
    root_public_key: str | None = None,
) -> Report:
    registry = CHECKS if registry is None else registry
    if len(set(checks)) != len(checks) or any(name not in registry for name in checks):
        msg = "Duplicate or unknown configured provenance check"
        raise VerificationUnavailable(msg)
    reader = SubmissionReader(assignment_root, max_file_bytes)
    errors: tuple[str, ...] = ()
    try:
        directory = reader.recording_directory()
    except VerificationUnavailable as exc:
        directory = None
        errors = (str(exc),)
    scopes = () if directory is None else (directory,)
    context = VerificationContext(reader.root, assignment_id, expected_manifest, scopes, reader, root_public_key)
    results: list[CheckResult] = []
    for name in checks:
        try:
            result = registry[name](context)
            if not isinstance(result, CheckResult) or result.check != name:
                msg = "Checker returned an invalid or misidentified result"
                raise ValueError(msg)
            results.append(result)
        except Exception as exc:
            results.append(CheckResult(name, "error", f"{type(exc).__name__}: {str(exc)[:500]}"))
    return Report(tuple(path.relative_to(reader.root).as_posix() for path in scopes), tuple(results), errors)
