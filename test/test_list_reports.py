import unittest
import tempfile
import os

from pipeline.batch.list_reports import ListReportFiles
from pipeline.helpers.util import get_date_interval

class TestListReports(unittest.TestCase):

    def setUp(self):
        self.mother_directory = tempfile.mkdtemp()
        print self.mother_directory
        dir1 = os.path.join(self.mother_directory, "2013-01-01")
        dir2 = os.path.join(self.mother_directory, "2013-01-02")
        dir3 = os.path.join(self.mother_directory, "2014-01-01")
        os.mkdir(dir1)
        os.mkdir(dir2)
        os.mkdir(dir3)

        filenames1 = ["20130101T000000Z-AS00-dnstamper-v1-probe.yaml",
                      "20130101T000000Z-AS00-tcpconnect-v1-probe.yaml",
                      "20130101T000000Z-AS00-http_requests-v1-probe.yaml",
                      "20130101T000000Z-AS00-http_requests-v1-probe.yaml",
                      "20130101T000000Z-AS00-dnstamper-v1-probe.yaml",
                      "20130101T000000Z-AS00-dnstamper-v1-probe.yaml"]
        filenames2 = ["20130102T000000Z-AS00-dnstamper-v1-probe.yaml",
                      "20130102T000000Z-AS00-tcpconnect-v1-probe.yaml",
                      "20130102T000000Z-AS00-http_requests-v1-probe.yaml",
                      "20130102T000000Z-AS00-http_requests-v1-probe.yaml",
                      "20130102T000000Z-AS00-dnstamper-v1-probe.yaml",
                      "20130102T000000Z-AS00-dnstamper-v1-probe.yaml"]
        filenames3 = ["20140101T000000Z-AS00-dnstamper-v1-probe.yaml",
                      "20140101T000000Z-AS00-tcpconnect-v1-probe.yaml",
                      "20140101T000000Z-AS00-http_requests-v1-probe.yaml",
                      "20140101T000000Z-AS00-http_requests-v1-probe.yaml",
                      "20140101T000000Z-AS00-dnstamper-v1-probe.yaml",
                      "20140101T000000Z-AS00-dnstamper-v1-probe.yaml"]

        for filename in filenames1:
            open(os.path.join(dir1, filename), 'a').close()
        for filename in filenames2:
            open(os.path.join(dir2, filename), 'a').close()
        for filename in filenames3:
            open(os.path.join(dir3, filename), 'a').close()

    def test_list_report(self):
        dateinterval = get_date_interval('2013')
        print 11
        ListReportFiles(date_interval=dateinterval,
                        test_names=['http_requests'],
                        output_path=self.mother_directory,
                        report_path=self.mother_directory).run()

if __name__ == '__main__':
    unittest.main()
