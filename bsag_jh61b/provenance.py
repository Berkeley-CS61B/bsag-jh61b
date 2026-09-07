import json
import re
from dataclasses import asdict
from pathlib import Path

from bsag import BaseStepConfig, BaseStepDefinition
from bsag.bsagio import BSAGIO
from bsag.steps.gradescope import RESULTS_KEY, Results
from bsag.steps.gradescope._types import VisibilityEnum
from pydantic import Field, PositiveInt

from .provenance_verify import DEFAULT_MAX_FILE_BYTES, Report, verify_assignment

PROVENANCE_REPORT_KEY = "jh61b_provenance_report"
SCOPE_BOUNDARY = "Checks concern recording integrity only, submitted-code matching and behavior are not evaluated."


class ProvenanceConfig(BaseStepConfig):
    halt_on_fail: bool = True
    assignment_id: str = Field(min_length=1)
    expected_manifest: Path
    assignment_root: Path
    checks: list[str] = Field(default_factory=list)
    fail_open: bool = True
    max_file_bytes: PositiveInt = DEFAULT_MAX_FILE_BYTES


def _expected_signature(config: ProvenanceConfig) -> str:
    path = config.expected_manifest.resolve(strict=True)
    if path.is_relative_to(config.assignment_root.resolve()):
        msg = "expected_manifest must be outside the student submission"
        raise ValueError(msg)
    with path.open("rb") as stream:
        data = stream.read(1024 * 1024 + 1)
    if len(data) > 1024 * 1024:
        msg = "Trusted assignment manifest exceeds 1 MiB"
        raise ValueError(msg)
    manifest = json.loads(data)
    if not isinstance(manifest, dict) or manifest.get("assignment_id") != config.assignment_id:
        msg = "Trusted manifest assignment_id does not match the configured assignment"
        raise ValueError(msg)
    signature = manifest.get("sig")
    if not isinstance(signature, str) or re.fullmatch(r"[0-9a-fA-F]{128}", signature) is None:
        msg = "Trusted manifest has no valid Ed25519 signature encoding"
        raise ValueError(msg)
    return signature


class Provenance(BaseStepDefinition[ProvenanceConfig]):
    @staticmethod
    def name() -> str:
        return "jh61b.provenance"

    @classmethod
    def display_name(cls, _config: ProvenanceConfig) -> str:
        return "Provenance integrity"

    @classmethod
    def run(cls, bsagio: BSAGIO, config: ProvenanceConfig) -> bool:
        results: Results = bsagio.data.setdefault(RESULTS_KEY, Results())
        results.stdout_visibility = VisibilityEnum.HIDDEN
        try:
            expected_sig = _expected_signature(config)
            report = verify_assignment(
                config.assignment_root,
                config.assignment_id,
                expected_sig,
                checks=config.checks,
                max_file_bytes=config.max_file_bytes,
            )
        except Exception as exc:
            bsagio.private.exception("Provenance infrastructure could not complete")
            report = Report(errors=(f"{type(exc).__name__}: {str(exc)[:500]}",))

        bsagio.data[PROVENANCE_REPORT_KEY] = report
        bsagio.private.info(SCOPE_BOUNDARY)
        bsagio.private.info(
            "Provenance outcome={} scopes={} selected_checks={} evaluated_checks={}",
            report.outcome,
            len(report.scopes),
            len(config.checks),
            len(report.checks),
        )
        for scope in report.scopes:
            bsagio.private.info("Provenance scope={}", json.dumps(scope[:500], ensure_ascii=True))
        for result in report.checks:
            bsagio.private.info(
                "Provenance check={} outcome={} detail={}",
                json.dumps(result.check[:100]),
                result.outcome,
                json.dumps(result.detail[:1000]),
            )
        for finding in report.flags[:100]:
            evidence = {
                key: value[:1000] if isinstance(value, str) else value for key, value in asdict(finding).items()
            }
            bsagio.private.warning("Provenance finding={}", json.dumps(evidence, ensure_ascii=True))
        if len(report.flags) > 100:
            bsagio.private.warning("Further findings omitted from stdout, complete report is in BSAG data")
        for error in report.errors:
            bsagio.private.warning("Provenance unavailable={}", json.dumps(error[:1000]))

        if report.outcome == "flagged":
            action = "grading has stopped" if config.halt_on_fail else "grading continues for staff review"
            bsagio.student.error(f"Your Provenance recording could not be verified, {action}.")
            return False
        if report.outcome == "error":
            action = "grading has stopped" if config.halt_on_fail and not config.fail_open else "grading continues"
            bsagio.student.info(f"Provenance integrity checking is unavailable, {action}.")
            return config.fail_open
        if report.outcome == "not_evaluated":
            if not config.checks:
                bsagio.student.info("Provenance integrity checks are not enabled, grading continues.")
            else:
                bsagio.student.info("Provenance integrity checking is incomplete, grading continues.")
            return True
        bsagio.student.success("The enabled Provenance integrity checks passed.")
        return True
