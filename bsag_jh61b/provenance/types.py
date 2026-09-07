from __future__ import annotations

from collections.abc import Callable, Mapping
from dataclasses import dataclass, field
from functools import cached_property
from pathlib import Path
from typing import TYPE_CHECKING, Literal

if TYPE_CHECKING:
    from .io import SubmissionReader

Outcome = Literal["passed", "flagged", "not_evaluated", "error"]


class VerificationUnavailable(Exception):
    """The Provenance verification could not complete, this is not a tampering finding."""


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


@dataclass(frozen=True)
class FileStructure:
    manifest_kind: str
    recording_kind: str
    entries: Mapping[str, str]


@dataclass(frozen=True)
class VerificationContext:
    assignment_root: Path
    assignment_id: str
    expected_sig: str
    scopes: tuple[Path, ...]
    reader: SubmissionReader = field(repr=False)

    @cached_property
    def structure(self) -> FileStructure:
        from .io import inspect_structure

        return inspect_structure(self.assignment_root)


Check = Callable[[VerificationContext], CheckResult]
