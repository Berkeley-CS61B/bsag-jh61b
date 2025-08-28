from pathlib import Path
from typing import Any

from bsag import BaseStepDefinition
from bsag.bsagio import BSAGIO
from pydantic import validator

from ._types import PIECES_KEY, AssessmentPieces, BaseJh61bConfig, FailedPiece, Piece


class CheckFilesConfig(BaseJh61bConfig):
    pieces: dict[str, Piece]

    @validator("pieces")
    def grader_does_not_have_student_files(cls, v: dict[str, Piece], values: dict[str, Any]) -> dict[str, Piece]:
        grader_root: Path = values["grader_root"]
        bad_files: set[str] = set()
        for piece in v.values():
            for file in piece.student_files:
                grader_file = Path(grader_root, file)
                if grader_file.is_file():
                    bad_files.add(str(grader_file))

        if bad_files:
            raise ValueError("Files marked for student submission found in grader:\n" + "\n".join(bad_files))

        return v


class CheckFiles(BaseStepDefinition[CheckFilesConfig]):
    @staticmethod
    def name() -> str:
        return "jh61b.check_files"

    @classmethod
    def display_name(cls, config: CheckFilesConfig) -> str:
        return "File Checking"

    @classmethod
    def run(cls, bsagio: BSAGIO, config: CheckFilesConfig) -> bool:
        pieces = AssessmentPieces()

        # First, check if the submission directory itself exists.
        if not config.submission_root.is_dir():
            bsagio.both.error(f"Submission directory not found: {config.submission_root}")
            
            # For extra debugging help, show what IS in the parent submission folder
            submission_parent = Path("/autograder/submission")
            if submission_parent.is_dir():
                contents = [p.name for p in submission_parent.iterdir()]
                bsagio.both.info(f"Contents of {submission_parent}: {contents}")
            
            # Fail all pieces because the root directory is missing
            pieces = AssessmentPieces()
            for name in config.pieces:
                pieces.piece_names.append(name)
                pieces.failed_pieces[name] = FailedPiece(reason="submission directory not found")
            bsagio.data[PIECES_KEY] = pieces
            return False
        
        # Now that we've established that the submission directory exists, heck that required files exist
        for name, piece in config.pieces.items():
            pieces.piece_names.append(name)
            if all(Path(config.submission_root, f).is_file() for f in piece.student_files):
                piece.student_files = {Path(config.submission_root, f) for f in piece.student_files}
                piece.assessment_files = {Path(config.grader_root, f) for f in piece.assessment_files}
                pieces.live_pieces[name] = piece
            else:
                pieces.failed_pieces[name] = FailedPiece(reason="missing required files")
                bsagio.both.error(f"Missing required files for assessment {name}:")
                for file in piece.student_files:
                    if not file.is_file():
                        bsagio.both.error(f"- {file}")

        bsagio.data[PIECES_KEY] = pieces

        return len(config.pieces) == len(pieces.live_pieces)
