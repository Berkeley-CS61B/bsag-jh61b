import json
import os
import tempfile
from subprocess import list2cmdline

from bsag import BaseStepDefinition
from bsag.bsagio import BSAGIO
from bsag.steps.gradescope import METADATA_KEY, Results, SubmissionMetadata, TestCaseStatusEnum, TestResult
from bsag.utils.subprocesses import run_subprocess
from pydantic import BaseModel, PositiveInt

from ._types import PIECES_KEY, TEST_RESULTS_KEY, AssessmentPieces, BaseJh61bConfig, Jh61bResults
from .java_utils import path_to_classname


class PieceAssessmentConfig(BaseModel):
    java_options: list[str] = []
    args: list[str] = []
    command_timeout: PositiveInt | None = None
    require_full_score: bool = False
    aggregated_number: str | None = None


class AssessmentConfig(BaseJh61bConfig):
    piece_configs: dict[str, PieceAssessmentConfig] = {}
    default_java_options: list[str] = []
    command_timeout: PositiveInt | None = None


class Assessment(BaseStepDefinition[AssessmentConfig]):
    @staticmethod
    def name() -> str:
        return "jh61b.assessment"

    @classmethod
    def display_name(cls, config: AssessmentConfig) -> str:
        return "Assessment"

    @classmethod
    def run(cls, bsagio: BSAGIO, config: AssessmentConfig) -> bool:
        pieces: AssessmentPieces = bsagio.data[PIECES_KEY]
        sub_meta: SubmissionMetadata = bsagio.data[METADATA_KEY]

        all_success = True

        for piece_name in pieces.piece_names:
            piece_config = config.piece_configs.get(piece_name, PieceAssessmentConfig())

            if piece_name not in pieces.live_pieces:
                if piece_name in pieces.failed_pieces:
                    reason = pieces.failed_pieces[piece_name].reason
                else:
                    reason = "unknown piece name"

                bsagio.both.error(f"Unable to run assessment for {piece_name}: {reason}")
                all_success = False
                continue

            bsagio.private.info(f"Testing {piece_name}...")

            java_properties = {
                "bsag.grader.classroot": config.grader_root,
                "bsag.submission.classroot": config.submission_root,
                "bsag.student.email": ",".join(s.email for s in sub_meta.users),
                "bsag.student.name": ",".join(s.name for s in sub_meta.users),
            }
            java_options = [f"-D{k}={v}" for k, v in java_properties.items()]
            java_options += config.default_java_options
            java_options += piece_config.java_options

            classpath = f"{config.grader_root}:{config.submission_root}:{os.environ.get('CLASSPATH')}"

            piece = pieces.live_pieces[piece_name]
            test_results: list[TestResult] = []
            _, outfile = tempfile.mkstemp(suffix=".json", prefix="assess")
            for assessment_file in piece.assessment_files:
                assessment_class = path_to_classname(assessment_file.relative_to(config.grader_root))

                assessment_command = ["java"] + java_options
                assessment_command += ["-classpath", classpath, assessment_class]
                assessment_command += ["--secure", "--json", "--outfile", outfile]
                assessment_command += piece_config.args

                bsagio.private.debug("\n" + list2cmdline(assessment_command))

                if piece_config.command_timeout is not None:
                    timeout = piece_config.command_timeout
                else:
                    timeout = config.command_timeout

                # Grader may use relative paths, so use cwd
                result = run_subprocess(
                    assessment_command,
                    cwd=config.grader_root,
                    timeout=timeout,
                )
                if result.timed_out:
                    bsagio.private.error(f"timed out while running {assessment_class}")
                    bsagio.student.error(
                        f"Your submission timed out on the test suite {assessment_class}.\n"
                        "Please make sure your code terminates on all inputs, and doesn't take too long to do so."
                    )
                    all_success = False
                    continue
                # This won't execute just due to tests failing. `jh61b` is a test harness that wraps those failures.
                # Instead, we get a bad return code if:
                # - The test was killed by external timeout (see above)
                # - The JVM killed the test due to heap memory
                # - The harness itself errors (unlikely)
                # - The test or code under test calls `System.exit` (likely)
                if result.return_code != 0:
                    all_success = False
                    bsagio.private.error(f"process died with code {result.return_code} running {assessment_class}")
                    if result.return_code > 128 or result.return_code < 0:
                        bsagio.student.error(
                            f"Your submission failed to complete on the test suite {assessment_class}.\n"
                            "You're most likely using too much memory."
                        )
                    else:
                        # If we got system.err'd, expose the output.
                        bsagio.student.error(f"In piece {piece_name}, test {assessment_class} exited with an error:")
                        bsagio.student.error(result.output)
                    continue

                # jh61b produces an entire Results, but we may have multiple Assessments.
                try:
                    with open(outfile, encoding="utf-8") as f:
                        test_json = json.load(f)
                    results = Results.parse_obj(test_json)
                    test_results.extend(results.tests)
                except json.JSONDecodeError:
                    bsagio.private.error(f"Error decoding output for {assessment_class}")
                    bsagio.private.error("\n" + result.output)
                    bsagio.student.error("Unexpected error while running assessment; details in staff logs.")

                    all_success = False
                    continue

            score = 0.0
            max_score = 0.0
            for test in test_results:
                score += test.score or 0
                max_score += test.max_score or 0

            bsagio.private.info(f"Scored {score:.3f} / {max_score:.3f} points on {piece_name}")

            if TEST_RESULTS_KEY not in bsagio.data:
                bsagio.data[TEST_RESULTS_KEY] = {}

            if piece_config.require_full_score:
                if score != max_score:
                    bsagio.private.info(f"{piece_name} requires full score to receive credit.")
                    score = 0

                failed_tests: list[str] = []
                for test in test_results:
                    if test.score != test.max_score:
                        test.status = TestCaseStatusEnum.FAILED
                        failed_tests.append(
                            "- " + (test.number if test.number else "") + (test.name if test.name else "Unnamed test")
                        )
                    test.score = None
                    test.max_score = None

                output_chunks = [
                    f"{piece_name} requires full score to receive credit.",
                ]
                if failed_tests:
                    output_chunks.append("Failing the following tests:")
                    output_chunks.extend(failed_tests)

                test_results.insert(
                    0,
                    TestResult(
                        name=piece_name,
                        number=piece_config.aggregated_number,
                        score=score,
                        max_score=max_score,
                        output="\n".join(output_chunks),
                    ),
                )

            bsagio.data[TEST_RESULTS_KEY][piece_name] = Jh61bResults(
                score=score, max_score=max_score, tests=test_results
            )

            if not piece_config.require_full_score and score != max_score:
                all_success = False

        return all_success
