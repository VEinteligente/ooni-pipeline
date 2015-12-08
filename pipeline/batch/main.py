import luigi
import logging

from luigi.configuration import get_config

from .full_db_import import ImportYAMLReportsToDatabase

config = get_config()
logger = logging.getLogger('luigi-interface')


class MainPipelineTask(luigi.Task):

    incoming_dir = luigi.Parameter()
    public_dir = luigi.Parameter()
    private_dir = luigi.Parameter()
    move = luigi.BoolParameter(default=False)

    def run(self):
        yield ImportYAMLReportsToDatabase(
            incoming_dir=self.incoming_dir,
            private_dir=self.private_dir,
            public_dir=self.public_dir,
            move=self.move
        )
