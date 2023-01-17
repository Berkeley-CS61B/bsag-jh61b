import re
from pathlib import Path

from bsag import BaseStepDefinition
from bsag.bsagio import BSAGIO

from ._types import BaseJh61bConfig


class MagicWordConfig(BaseJh61bConfig):
    magic_word_path: Path = Path("magic_word.txt")
    magic_word_regex: str | list[str] = []


class MagicWord(BaseStepDefinition[MagicWordConfig]):
    @staticmethod
    def name() -> str:
        return "jh61b.magic_word"

    @classmethod
    def display_name(cls, config: MagicWordConfig) -> str:
        return "Magic Word"

    @classmethod
    def run(cls, bsagio: BSAGIO, config: MagicWordConfig) -> bool:
        magic_word_file = Path(config.submission_root, config.magic_word_path).resolve()

        magic_word_regex = config.magic_word_regex
        if type(magic_word_regex) is str:
            magic_word_regex = [magic_word_regex]

        if not magic_word_file.is_file():
            bsagio.both.error(f"{config.magic_word_path} does not exist!")
            return False

        with open(magic_word_file) as f:
            contents = f.read().strip()
            if not contents:
                bsagio.both.error(f"{config.magic_word_path} was empty!")
                return False

            bsagio.both.info(f"Found magic word {contents}")
            for pattern in magic_word_regex:
                if re.fullmatch(pattern, contents):
                    bsagio.both.success("... correct!")
                    return True

            bsagio.both.error("... but it wasn't correct! Make sure you spelled it correctly.")

        return False
