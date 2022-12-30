import random

import yaml
from bsag import BaseStepConfig, BaseStepDefinition
from bsag.bsagio import BSAGIO
from bsag.steps.gradescope import METADATA_KEY, RESULTS_KEY, Results, SubmissionMetadata
from pydantic import FilePath


class MotdConfig(BaseStepConfig):
    path: FilePath


class Motd(BaseStepDefinition[MotdConfig]):
    @staticmethod
    def name() -> str:
        return "jh61b.motd"

    @classmethod
    def run(cls, bsagio: BSAGIO, config: MotdConfig) -> bool:
        data = bsagio.data
        with open(config.path, encoding="utf-8") as file:
            motds = yaml.safe_load(file)

        sub_meta: SubmissionMetadata = data[METADATA_KEY]
        random.seed(sub_meta.created_at.timestamp())
        motd = random.choice(motds)

        results: Results = data[RESULTS_KEY]
        results.output = motd

        return True
