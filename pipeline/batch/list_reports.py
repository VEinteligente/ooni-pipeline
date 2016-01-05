import os

import luigi
from pipeline.helpers.util import list_report_files, get_luigi_target

class ListReportFiles(luigi.Task):
    test_names = luigi.Parameter()
    date_interval = luigi.DateIntervalParameter()

    output_path = luigi.Parameter(default="/data/ooni/")
    report_path = luigi.Parameter(default="/data/ooni/private/reports-raw/json/")

    def output(self):
        path = os.path.join(
            self.output_path,
            "reports-{}-{}.txt".format(self.test_names, self.date_interval)
        )
        return get_luigi_target(path)

    def run(self):
        out_file = self.output().open('w')
        for date in self.date_interval:
            for report_file_path in list_report_files(
                os.path.join(self.report_path, date.strftime("%Y-%m-%d")),
                report_extensions=(".json", ".yaml")
            ):
                test_name = os.path.basename(report_file_path).split("-")[-3]
                if test_name in self.test_names:
                    out_file.write("%s\n" % report_file_path)
        out_file.close()
