import re
from pathlib import Path
from subprocess import list2cmdline

import pathspec
from bsag import BaseStepConfig, BaseStepDefinition
from bsag.bsagio import BSAGIO
from bsag.utils.subprocesses import run_subprocess
from pydantic import FilePath, PositiveInt

WARNING_MSG_PAT = re.compile(r"^\[ERROR\]\s*(?P<error>.*)")


class CheckStyleConfig(BaseStepConfig):
    checkstyle_jar_path: FilePath | None
    checkstyle_xml_path: FilePath
    submission_root: Path
    pathspec: list[str] = ["*.java"]
    command_timeout: PositiveInt


class CheckStyle(BaseStepDefinition[CheckStyleConfig]):
    @staticmethod
    def name() -> str:
        return "jh61b.checkstyle"

    @classmethod
    def display_name(cls, config: CheckStyleConfig) -> str:
        return "Style"

    @classmethod
    def run(cls, bsagio: BSAGIO, config: CheckStyleConfig) -> bool:
        # Need a new release of pathspec for stubs
        filespec: pathspec.PathSpec = pathspec.PathSpec.from_lines("gitwildmatch", config.pathspec)
        files = [Path(config.submission_root, f) for f in filespec.match_tree(config.submission_root)]  # type: ignore
        files.sort()

        bsagio.both.info(f"Running style check on {len(files)}")

        passed = True
        total_errors = 0
        # Run checkstyle separately for each file, because if checkstyle finds a syntax error, it halts entirely.
        for file in files:
            style_command: list[str | Path] = ["java"]
            if config.checkstyle_jar_path:
                style_command += ["-jar", config.checkstyle_jar_path]
            else:
                style_command += ["com.puppycrawl.tools.checkstyle.Main"]
            style_command += ["-c", config.checkstyle_xml_path, file]
            bsagio.private.debug("\n" + list2cmdline(style_command))
            style_result = run_subprocess(style_command, timeout=config.command_timeout)
            if style_result.timed_out:
                bsagio.both.error(f"Timed out while style-checking {file}.")
                passed = False
            elif style_result.return_code != 0:
                passed = False
                style_errors = 0
                for line in style_result.output.splitlines():
                    match = WARNING_MSG_PAT.match(line)
                    if match is None:
                        continue
                    style_errors += 1
                    bsagio.student.error(match.group("error").removeprefix(str(config.submission_root)))
                if style_errors == 0:
                    bsagio.both.error(f"Style checking {file} failed for non-style reasons.")
                    bsagio.private.error(style_result.output)
                    passed = False
                total_errors += style_errors

        return passed
