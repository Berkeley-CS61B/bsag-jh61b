import os
import stat
from pathlib import Path
from types import MappingProxyType

from .types import FileStructure, VerificationUnavailable

DEFAULT_MAX_FILE_BYTES = 32 * 1024 * 1024


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


def _kind(path: Path) -> str:
    try:
        info = path.lstat()
    except FileNotFoundError:
        return "missing"
    if _is_link(info):
        return "other"
    if stat.S_ISREG(info.st_mode):
        return "file"
    if stat.S_ISDIR(info.st_mode):
        return "directory"
    return "other"


def inspect_structure(root: Path) -> FileStructure:
    manifest_kind = _kind(root / "provenance-manifest")
    directory = root / ".provenance"
    recording_kind = _kind(directory)
    entries = {}
    if recording_kind == "directory":
        with os.scandir(directory) as children:
            for child in children:
                info = child.stat(follow_symlinks=False)
                entries[child.name] = "file" if stat.S_ISREG(info.st_mode) and not _is_link(info) else "other"
    return FileStructure(manifest_kind, recording_kind, MappingProxyType(entries))
