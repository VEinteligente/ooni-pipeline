import os
import re
import json
import hashlib

import luigi

from pipeline.helpers.util import get_luigi_target, json_dumps, json_loads
from .list_reports import ListReportFiles

class SanitiseReportsTask(luigi.Task):
    date_interval = luigi.DateIntervalParameter()

    output_report_list_path = luigi.Parameter(default="/data/ooni/")
    input_report_path = luigi.Parameter(default="/data/ooni/private/reports-raw/json/")
    output_report_path = luigi.Parameter(default="/data/ooni/public/reports-sanitised/json/")

class SanitiseBridgeReachability(SanitiseReportsTask):
    bridge_db_path = luigi.Parameter(default="/data/ooni/private/bridge_reachability/bridge_db.json")

    def output(self):
        path = os.path.join(
            self.output_report_path,
            "bridge_reachability-{}.json.gz".format(self.date_interval)
        )
        return get_luigi_target(path)

    def requires(self):
        test_names = [
            "tcp_connect",
            "bridge_reachability"
        ]
        return ListReportFiles(output_path=self.ouput_report_list_path,
                               report_path=self.input_report_path,
                               date_interval=self.date_interval,
                               test_names=test_names)

    def sanitise_bridge_reachability(self, entry, bridge_db):
        if not entry.get('bridge_address'):
            entry['bridge_address'] = entry['input']

        if entry['bridge_address'] and \
                entry['bridge_address'].strip() in bridge_db:
            b = bridge_db[entry['bridge_address'].strip()]
            entry['distributor'] = b['distributor']
            entry['transport'] = b['transport']
            fingerprint = b['fingerprint'].decode('hex')
            hashed_fingerprint = hashlib.sha1(fingerprint).hexdigest()
            entry['input'] = hashed_fingerprint
            entry['bridge_address'] = None
            regexp = ("(Learned fingerprint ([A-Z0-9]+)"
                    "\s+for bridge (([0-9]+\.){3}[0-9]+\:\d+))|"
                    "((new bridge descriptor .+?\s+"
                    "at (([0-9]+\.){3}[0-9]+)))")
            if entry.get('tor_log'):
                entry['tor_log'] = re.sub(regexp, "[REDACTED]", entry['tor_log'])
            else:
                entry['tor_log'] = None
        else:
            entry['distributor'] = None
            hashed_fingerprint = None

        entry['bridge_hashed_fingerprint'] = hashed_fingerprint

        return entry

    def sanitise_tcp_connect(self, entry, bridge_db):
        if entry['input'] and entry['input'].strip() in bridge_db.keys():
            b = bridge_db[entry['input'].strip()]
            fingerprint = b['fingerprint'].decode('hex')
            hashed_fingerprint = hashlib.sha1(fingerprint).hexdigest()
            entry['bridge_hashed_fingerprint'] = hashed_fingerprint
            entry['input'] = hashed_fingerprint
            return (True, entry)
        return (False, entry)

    def run(self):
        with get_luigi_target(self.bridge_db_path).open('r') as f:
            bridge_db = json.load(f)

        in_file = self.input().open('r')
        out_file = self.output().open('w')
        for line in in_file:
            report_path = line.strip()
            with get_luigi_target(report_path).open('r') as report_file:
                for report_line in report_file:
                    bridge_test = False
                    entry = json_loads(report_line.strip())
                    if entry['test_name'] == 'tcp_connect':
                        bridge_test, entry = self.sanitise_tcp_connect(entry,
                                                                       bridge_db)
                    elif entry['test_name'] == 'bridge_reachability':
                        entry = self.sanitise_bridge_reachability(entry, bridge_db)
                        bridge_test = True

                    if bridge_test:
                        out_file.write(json_dumps(entry))
                        out_file.write("\n")
