import os

import luigi
from luigi.configuration import get_config

from pipeline.helpers.util import list_report_files, get_luigi_target

class ListReportFiles(luigi.Task):
    test_names = luigi.Parameter()
    date_interval = luigi.DateIntervalParameter()

    output_path = luigi.Parameter(default="/data/ooni/working-dir/")
    report_path = luigi.Parameter(default="/data/ooni/private/reports-raw/json/")

    def output(self):
        path = os.path.join(
            self.output_path,
            "report-list-{}-{}.txt".format(
                self.date_interval,
                '-'.join(self.test_names)
            )
        )
        return get_luigi_target(path)

    def run(self):
        config = get_config()
        out_file = self.output().open('w')
        for date in self.date_interval:
            for report_file_path in list_report_files(
                os.path.join(self.report_path, date.strftime("%Y-%m-%d")),
                aws_access_key_id=config.get('s3', 'aws_access_key_id'),
                aws_secret_access_key=config.get('s3', 'aws_secret_access_key'),
                report_extensions=(".json", ".yaml")
            ):
                test_name = os.path.basename(report_file_path).split("-")[-3]
                if test_name in self.test_names:
                    out_file.write("%s\n" % report_file_path)
        out_file.close()
