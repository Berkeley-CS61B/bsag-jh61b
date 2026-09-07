import os
import stat
from collections.abc import Callable, Mapping, Sequence
from dataclasses import dataclass, field
from pathlib import Path
from types import MappingProxyType
from typing import Literal

Outcome = Literal["passed", "flagged", "not_evaluated", "error"]


class VerificationUnavailable(Exception):
    """The Provenance verification could not complete, this is not a tampering finding."""


DEFAULT_MAX_FILE_BYTES = 32 * 1024 * 1024


@dataclass(frozen=True)
class Finding:
    check: str
    detail: str
    scope: str | None = None


@dataclass(frozen=True)
class CheckResult:
    check: str
    outcome: Outcome
    detail: str = ""
    findings: tuple[Finding, ...] = ()

    def __post_init__(self) -> None:
        if self.outcome not in ("passed", "flagged", "not_evaluated", "error"):
            msg = "Unknown check outcome"
            raise ValueError(msg)
        if (self.outcome == "flagged") != bool(self.findings):
            msg = "Only a flagged result may contain findings, and it must contain at least one"
            raise ValueError(msg)
        if any(finding.check != self.check for finding in self.findings):
            msg = "Findings must identify their producing check"
            raise ValueError(msg)


@dataclass(frozen=True)
class Report:
    scopes: tuple[str, ...] = ()
    checks: tuple[CheckResult, ...] = ()
    errors: tuple[str, ...] = ()

    @property
    def flags(self) -> tuple[Finding, ...]:
        return tuple(finding for result in self.checks for finding in result.findings)

    @property
    def outcome(self) -> Outcome:
        if self.flags:
            return "flagged"
        if self.errors or any(result.outcome == "error" for result in self.checks):
            return "error"
        if not self.checks or any(result.outcome == "not_evaluated" for result in self.checks):
            return "not_evaluated"
        return "passed"


def _is_link(info: os.stat_result) -> bool:
    return stat.S_ISLNK(info.st_mode) or bool(getattr(info, "st_file_attributes", 0) & 0x400)


class SubmissionReader:
    def __init__(self, root: Path, max_file_bytes: int = DEFAULT_MAX_FILE_BYTES) -> None:
        if type(max_file_bytes) is not int or max_file_bytes <= 0:
            msg = "max_file_bytes must be a positive integer"
            raise ValueError(msg)
        root = root.absolute()
        if _is_link(root.lstat()) or not root.is_dir():
            msg = "Submission root is not an ordinary directory"
            raise VerificationUnavailable(msg)
        self.root = root.resolve(strict=True)
        self.max_file_bytes = max_file_bytes

    def _path(self, path: Path) -> Path:
        candidate = path if path.is_absolute() else self.root / path
        try:
            relative = candidate.relative_to(self.root)
        except ValueError as exc:
            msg = "Read outside submission root refused"
            raise VerificationUnavailable(msg) from exc
        if ".." in relative.parts:
            msg = "Parent traversal refused"
            raise VerificationUnavailable(msg)
        current = self.root
        for part in relative.parts:
            current /= part
            if _is_link(current.lstat()):
                msg = "Read through a symlink or junction refused"
                raise VerificationUnavailable(msg)
        return candidate

    def read_bytes(self, path: Path) -> bytes:
        candidate = self._path(path)
        info = candidate.lstat()
        if not stat.S_ISREG(info.st_mode):
            msg = "Only regular submission files may be read"
            raise VerificationUnavailable(msg)
        if info.st_size > self.max_file_bytes:
            msg = "Provenance file byte limit exceeded"
            raise VerificationUnavailable(msg)
        flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_NONBLOCK", 0)
        flags |= getattr(os, "O_BINARY", 0)
        with os.fdopen(os.open(candidate, flags), "rb") as stream:
            if not stat.S_ISREG(os.fstat(stream.fileno()).st_mode):
                msg = "Only regular submission files may be read"
                raise VerificationUnavailable(msg)
            data = stream.read(self.max_file_bytes + 1)
            if len(data) > self.max_file_bytes:
                msg = "Provenance file byte limit exceeded"
                raise VerificationUnavailable(msg)
            return data

    def recording_directory(self) -> Path | None:
        try:
            directory = self._path(Path(".provenance"))
        except FileNotFoundError:
            return None
        if not directory.is_dir():
            msg = "The assignment's .provenance path is not a directory"
            raise VerificationUnavailable(msg)
        return directory


@dataclass(frozen=True)
class VerificationContext:
    assignment_root: Path
    assignment_id: str
    expected_sig: str
    scopes: tuple[Path, ...]
    reader: SubmissionReader = field(repr=False)


Check = Callable[[VerificationContext], CheckResult]
CHECKS: Mapping[str, Check] = MappingProxyType({})


def verify_assignment(
    assignment_root: Path,
    assignment_id: str,
    expected_sig: str,
    *,
    checks: Sequence[str] = (),
    max_file_bytes: int = DEFAULT_MAX_FILE_BYTES,
    registry: Mapping[str, Check] | None = None,
) -> Report:
    registry = CHECKS if registry is None else registry
    if len(set(checks)) != len(checks) or any(name not in registry for name in checks):
        msg = "Duplicate or unknown configured provenance check"
        raise VerificationUnavailable(msg)
    reader = SubmissionReader(assignment_root, max_file_bytes)
    directory = reader.recording_directory()
    scopes = () if directory is None else (directory,)
    context = VerificationContext(reader.root, assignment_id, expected_sig, scopes, reader)
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
    return Report(tuple(path.relative_to(reader.root).as_posix() for path in scopes), tuple(results))
