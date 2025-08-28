# note: This code was entirely LLM generated and never seriously reviewed
from pathlib import Path
import shutil

from bsag import BaseStepDefinition
from bsag.bsagio import BSAGIO

from ._types import BaseJh61bConfig


class CopyFromAlternateRootConfig(BaseJh61bConfig):
    """
    Configuration for jh61b.copy_from_alternate_root.

    Inherited:
      - grader_root: Path        (unused here)
      - submission_root: Path

    Additional:
      - alternate_root: Path     (directory to copy files *from*)
    """
    alternate_root: Path


class CopyFromAlternateRoot(BaseStepDefinition[CopyFromAlternateRootConfig]):
    @staticmethod
    def name() -> str:
        return "jh61b.copy_from_alternate_root"

    @classmethod
    def display_name(cls, config: CopyFromAlternateRootConfig) -> str:
        return "Copy from Alternate Root"

    @classmethod
    def run(cls, bsagio: BSAGIO, config: CopyFromAlternateRootConfig) -> bool:
        alt = config.alternate_root
        dest_root = config.submission_root

        # Nothing to do if the alternate root doesn't exist.
        if not alt.is_dir():
            bsagio.both.info(f"Alternate root not found; skipping copy: {alt}")
            return True

        # Ensure destination exists.
        try:
            dest_root.mkdir(parents=True, exist_ok=True)
        except Exception as e:
            bsagio.both.error(f"Could not create submission_root {dest_root}: {e}")
            return False

        # If they're the same directory, nothing to do.
        try:
            if alt.resolve() == dest_root.resolve():
                bsagio.both.info("alternate_root equals submission_root; nothing to copy.")
                return True
        except Exception:
            # If resolve() fails, proceed best-effort.
            pass

        num_copied = 0
        num_skipped = 0

        def copy_file(src: Path, dst_dir: Path) -> bool:
            """
            Copy a file into `dst_dir` without overwriting an existing file
            with the same name. Returns True if copied, False if skipped.
            """
            dst = dst_dir / src.name
            if dst.exists():
                bsagio.both.info(f"Skipping existing file: {dst}")
                return False
            try:
                shutil.copy2(src, dst)
                bsagio.both.info(f"Copied {src} -> {dst}")
                return True
            except Exception as e:
                bsagio.both.error(f"Failed to copy {src} -> {dst}: {e}")
                return False

        # Copy only top-level files directly under alternate_root into submission_root.
        # (We deliberately do not descend into subdirectories.)
        try:
            for child in alt.iterdir():
                if child.is_file():
                    if copy_file(child, dest_root):
                        num_copied += 1
                    else:
                        num_skipped += 1
                else:
                    bsagio.both.info(f"Not copying directory {child}; only top-level files are copied.")
        except Exception as e:
            bsagio.both.error(f"Error while scanning alternate root {alt}: {e}")
            return False

        bsagio.both.info(
            f"copy_from_alternate_root summary: copied={num_copied}, "
            f"skipped_existing={num_skipped}, from={alt}, to={dest_root}"
        )
        return True
