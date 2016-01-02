import unittest
import tempfile
import time
import yaml
import os

from datetime import datetime

from pipeline.helpers.report import YAMLReport, JSONReport
from pipeline.batch import convert_reports_to_json

def create_dummy_reports(directory):
    reports = [
        {
            "date": datetime(2015, 10, 10),
            "probe_asn": "AS4242",
            "test_name": "foo_test",
            "entries": [
                {
                    "key": "value",
                    "nesting": {
                        "binary_data1": "\x00something",
                        "binary_data2": '\x10som\xaa\xaa\xff'
                    }
                },
            ]
        },
        {
            "date": datetime(2015, 11, 10),
            "probe_asn": "AS4240",
            "test_name": "bar_test",
            "entries": [
                {
                    "key": "value",
                    "something": "bar"
                }
            ]
        }
    ]
    report_files = []
    for report in reports:
        os.mkdir(os.path.join(directory, report['date'].strftime("%Y-%m-%d")))
        report_filename = os.path.join(
            directory,
            report['date'].strftime("%Y-%m-%d"),
            "%s-%s-%s-v1-probe.yaml" % (report['date'].strftime("%Y%m%dT%H%M%SZ"),
                     report['probe_asn'],
                     report['test_name'])
        )
        with open(report_filename, "w+") as fw:
            header = {
                "test_name": report["test_name"],
                "start_time": time.mktime(report["date"].timetuple()),
                "probe_asn": report["probe_asn"],
                "probe_cc": "US",
                "probe_ip": "127.0.0.1"
            }
            fw.write("---\n")
            yaml.dump(header, fw)
            fw.write("...\n")
            for entry in report['entries']:
                fw.write("---\n")
                yaml.dump(entry, fw)
                fw.write("...\n")
        report_files.append(report_filename)
    return report_files

class TestConvertToJSON(unittest.TestCase):
    def setUp(self):
        self.yaml_directory = tempfile.mkdtemp()
        self.json_directory = tempfile.mkdtemp()
        self.report_files = create_dummy_reports(self.yaml_directory)

    def test_parse_yaml_report(self):
        for report_file in self.report_files:
            with open(report_file) as f:
                yr = YAMLReport(f, report_file)
                for e in yr.entries():
                    assert 'probe_asn' in e.keys()

    def test_parse_json_report(self):
        entries = []
        for report_file in self.report_files:
            with open(report_file) as f:
                yr = JSONReport(f, report_file)
                entries += list(yr.entries())
        assert entries[0]["nesting"]['binary_data2'].keys() == ["data", "encoding"]
        assert entries[0]["nesting"]['binary_data1'].keys() == ["data", "encoding"]

    def test_convert_to_json(self):
        src_directory = self.yaml_directory
        dst_directory = self.json_directory
        convert_reports_to_json.run(src_directory, dst_directory)
        assert os.path.exists(os.path.join(dst_directory, "2015-10-10/20151010T000000Z-AS4242-foo_test-v1-probe.json")) == True
        assert os.path.exists(os.path.join(dst_directory, "2015-11-10/20151110T000000Z-AS4240-bar_test-v1-probe.json")) == True

if __name__ == '__main__':
    unittest.main()
