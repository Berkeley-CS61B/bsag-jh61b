from bsag import ParamBaseStep
from bsag.plugin import hookimpl

from .api import ApiCheck
from .assessment import Assessment
from .check_files import CheckFiles
from .compilation import Compilation
from .dependency_check import DepCheck
from .final_score import FinalScore
from .motd import Motd


@hookimpl  # type: ignore
def bsag_load_step_defs() -> list[type[ParamBaseStep]]:
    return [
        ApiCheck,
        Assessment,
        CheckFiles,
        Compilation,
        DepCheck,
        FinalScore,
        Motd,
    ]
