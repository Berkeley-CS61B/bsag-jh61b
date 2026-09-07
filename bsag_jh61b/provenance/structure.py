import re

from .types import CheckResult, Finding, VerificationContext

_LOG = re.compile(r"session-([0-9a-f-]+)\.slog")


_META = re.compile(r"session-([0-9a-f-]+)\.slog\.meta")


_SEAL = re.compile(r"manifest-([0-9a-f-]+)\.(json|sig)")


_QUARANTINE = re.compile(r"(session-[0-9a-f-]+\.slog)\.corrupt-\d{4}-\d{2}-\d{2}T\d{2}-\d{2}-\d{2}-\d{3}Z")


_TEMP = re.compile(r"(.+)\.[0-9]+\.[0-9a-f]{16}\.tmp")


_AUXILIARY = {".gitattributes", ".DS_Store", "Thumbs.db", "desktop.ini"}


_CLASSIC = {"manifest.json", "manifest.sig"}


def _core_name(name: str) -> bool:
    return bool(_LOG.fullmatch(name) or _META.fullmatch(name) or _SEAL.fullmatch(name) or name in _CLASSIC)


def _allowed_name(name: str) -> bool:
    if _core_name(name) or name in _AUXILIARY or _QUARANTINE.fullmatch(name):
        return True
    temporary = _TEMP.fullmatch(name)
    return bool(temporary and _core_name(temporary[1]))


def _structural_result(check: str, details: list[str]) -> CheckResult:
    return CheckResult(
        check,
        "flagged" if details else "passed",
        detail="Filesystem structure only; file contents and signatures were not checked.",
        findings=tuple(Finding(check, detail, ".provenance") for detail in details),
    )


def invalid_structure(context: VerificationContext) -> CheckResult:
    structure = context.structure
    details = []
    if structure.manifest_kind not in ("missing", "file"):
        details.append("provenance-manifest is not an ordinary file")
    if structure.recording_kind not in ("missing", "directory"):
        details.append(".provenance is not an ordinary directory")
    details.extend(
        f".provenance/{name} is not an ordinary file"
        for name, kind in sorted(structure.entries.items())
        if kind != "file"
    )
    return _structural_result("invalid_structure", details)


def missing_files(context: VerificationContext) -> CheckResult:
    structure = context.structure
    details = []
    if structure.manifest_kind == "missing":
        details.append("Missing provenance-manifest in assignment root")
    if structure.recording_kind == "missing":
        details.append("Missing .provenance directory")
    if structure.recording_kind != "directory":
        if details:
            return _structural_result("missing_files", details)
        return CheckResult("missing_files", "not_evaluated", "Recording path has an invalid type")
    names = set(structure.entries)
    files = {name for name, kind in structure.entries.items() if kind == "file"}
    logs = {name for name in files if _LOG.fullmatch(name)}
    metas = {name for name in files if _META.fullmatch(name)}
    quarantined = {match[1] for name in files if (match := _QUARANTINE.fullmatch(name))}
    seals = {name for name in files if _SEAL.fullmatch(name)}
    if not any(log + ".meta" in files for log in logs):
        details.append("No complete log/sidecar pair")
    if not any(name.endswith(".json") and name[:-5] + ".sig" in files for name in seals):
        details.append("No complete rolling seal pair (Git recording format)")
    for log in sorted(logs):
        if log + ".meta" not in names:
            details.append(f"Missing companion {log}.meta")
    for meta in sorted(metas):
        log = meta[:-5]
        if log not in names and log not in quarantined:
            details.append(f"Missing companion {log}")
    for name in sorted(seals | (files & _CLASSIC)):
        companion = name[:-5] + ".sig" if name.endswith(".json") else name[:-4] + ".json"
        if companion not in names:
            details.append(f"Missing companion {companion}")
    return _structural_result("missing_files", details)


def unexpected_file(context: VerificationContext) -> CheckResult:
    structure = context.structure
    if structure.recording_kind != "directory":
        return CheckResult("unexpected_file", "not_evaluated", "Recording directory unavailable")
    details = [
        f"Unexpected file .provenance/{name}"
        for name, kind in sorted(structure.entries.items())
        if kind == "file" and not _allowed_name(name)
    ]
    return _structural_result("unexpected_file", details)
