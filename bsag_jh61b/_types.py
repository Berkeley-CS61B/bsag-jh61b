from pathlib import Path
from typing import Union

from bsag import BaseStepConfig
from bsag.steps.gradescope import TestResult
from pydantic import BaseModel

PIECES_KEY = "jh61b_pieces"
TEST_RESULTS_KEY = "jh61b_test_results"


class Piece(BaseModel):
    student_files: set[Path]
    assessment_files: set[Path]


class FailedPiece(BaseModel):
    reason: str


class AssessmentPieces(BaseModel):
    piece_names: list[str] = []
    live_pieces: dict[str, Piece] = {}
    failed_pieces: dict[str, FailedPiece] = {}


class BaseJh61bConfig(BaseStepConfig):
    grader_root: Path
    submission_root: Union[Path, list[Path]]
    
    def get_submission_roots(self) -> list[Path]:
        if isinstance(self.submission_root, Path):
            return [self.submission_root]
        return self.submission_root


class Jh61bResults(BaseModel):
    score: float
    max_score: float
    tests: list[TestResult]
