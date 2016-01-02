import os
import random
import traceback

from multiprocessing import Pool

from pipeline.helpers.util import json_dumps
from pipeline.helpers.util import list_report_files, get_luigi_target
from pipeline.helpers.report import JSONReport

def convert_report(report_filename, dst_directory, fail_log="fail.log"):
    try:
        input_target = get_luigi_target(report_filename)
        print("Converting %s" % report_filename)
        with input_target.open('r') as in_file:
            report = JSONReport(in_file, report_filename)
            output_filename = "{date}-{asn}-{test_name}-{df_version}-{ext}".format(
                date=report.report_date.strftime("%Y%m%dT%H%M%SZ"),
                asn=report.header["probe_asn"],
                test_name=report.header["test_name"],
                df_version="v1",
                ext="probe.json"
            )
            output_path = os.path.join(
                dst_directory,
                report.report_date.strftime("%Y-%m-%d"),
                output_filename
            )
            output_target = get_luigi_target(output_path)
            if output_target.exists():
                return
            out_file = output_target.open('w')
            for entry in report.entries():
                out_file.write(json_dumps(entry))
                out_file.write("\n")
            out_file.close()
    except Exception:
        with open(fail_log, "a+") as fw:
            fail_log_entry = {
                "exception": traceback.format_exc(),
                "filename": report_filename
            }
            fw.write(json_dumps(fail_log_entry))
            fw.write("\n")

class YAMLToJSONConverter(object):
    def __init__(self, src_directory, dst_directory, fail_log="fail.log", workers=4):
        self.src_directory = src_directory
        self.dst_directory = dst_directory
        self.fail_log = fail_log
        self.process_pool = Pool(processes=int(workers))
        self.report_files = None

    def list_reports(self):
        self.report_files = list(list_report_files(
            self.src_directory,
            aws_access_key_id=None,
            aws_secret_access_key=None,
            key_file=None,
            no_host_key_check=False)
        )
        #random.shuffle(self.report_files)

    def start_conversion(self):
        if self.report_files is None:
            self.list_reports()
        for report_file in self.report_files:
            self.process_pool.apply_async(convert_report, (report_file,
                                                           self.dst_directory,
                                                           self.fail_log))
        self.process_pool.close()
        self.process_pool.join()

def run(src_directory, dst_directory, fail_log, workers=4):
    yaml_to_json = YAMLToJSONConverter(src_directory, dst_directory, fail_log=fail_log, workers=workers)
    yaml_to_json.list_reports()
    yaml_to_json.start_conversion()
