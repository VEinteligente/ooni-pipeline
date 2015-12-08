import os
import json
import logging
import traceback

import luigi
import luigi.postgres
from luigi.configuration import get_config

from pipeline.helpers.report import Report
from pipeline.helpers.util import get_luigi_target, json_dumps, list_report_files


config = get_config()
logger = logging.getLogger('luigi-interface')


class YAMLReportFileToDatabase(luigi.postgres.CopyToTable):
    host = str(config.get('postgres', 'host'))
    database = str(config.get('postgres', 'database'))
    user = str(config.get('postgres','username'))
    password = str(config.get('postgres','password'))
    table = str(config.get('postgres','table'))

    columns = [
        ('input', 'TEXT'),
        ('report_id', 'TEXT'),
        ('report_filename', 'TEXT'),
        ('options', 'TEXT'),
        ('probe_cc', 'TEXT'),
        ('probe_asn', 'TEXT'),
        ('probe_ip', 'TEXT'),
        ('data_format_version', 'TEXT'),
        ('test_name', 'TEXT'),
        ('test_start_time', 'TEXT'),
        ('test_runtime', 'TEXT'),
        ('test_helpers', 'TEXT'),
        ('test_keys', 'JSON')
    ]

    report_filename = luigi.Parameter()

    bridge_db = {}

    def process_report(self, filename):
        target = get_luigi_target(filename)
        logger.info("Sanitising %s" % filename)
        with target.open('r') as in_file:
            report = Report(in_file, self.bridge_db, target.path)
            for sanitised_entry, raw_entry in report.process():
                try:
                    yield sanitised_entry
                except Exception:
                    logger.error("error in dumping %s" % filename)
                    logger.error(traceback.format_exc())

    def format_entry(self, entry):
        base_keys = [
            'input',
            'report_id',
            'report_filename',
            'options',
            'probe_cc',
            'probe_asn',
            'probe_ip',
            'data_format_version',
            'test_name',
            'test_start_time',
            'test_runtime',
            'test_helpers'
        ]

        keys = [k for k in base_keys]
        record = []
        for k in keys:
            record.append(entry.pop(k, None))
        record.append(json_dumps(entry))
        return record

    def get_bridge_db(self):
        bridge_db_path = config.get('ooni', 'bridge-db-path', None)
        if bridge_db_path:
            with get_luigi_target(bridge_db_path).open('r') as f:
                self.bridge_db = json.load(f)
        else:
            logger.warning("Will not sanitise bridge_reachability reports!")
            self.bridge_db = None

    def rows(self):
        self.get_bridge_db()
        try:
            for entry in self.process_report(self.report_filename):
                yield self.format_entry(entry)
        except Exception:
            logger.error("error in processing %s" % self.report_filename)
            logger.error(traceback.format_exc())

class ImportYAMLReportFromDateRange(luigi.ExternalTask):
    date_interval = luigi.DateIntervalParameter()
    private_dir = luigi.Parameter()

    def run(self):
        for date in self.date_interval:
            directory = os.path.join(
                self.private_dir,
                'reports-raw',
                'yaml',
                date.strftime("%Y-%m-%d")
            )
            logger.info("Listing directory %s" % directory)
            for filename in list_report_files(directory,
                                            aws_access_key_id=config.get('aws', 'access-key-id'),
                                            aws_secret_access_key=config.get('aws', 'secret-access-key')):
                logger.info("Looking at %s" % filename)
                yield YAMLReportFileToDatabase(report_filename=filename)
