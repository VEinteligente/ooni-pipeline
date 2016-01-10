import re
import os
import json
import hashlib

from datetime import datetime

import luigi

from luigi.configuration import get_config

from pipeline.helpers.util import list_report_files, get_luigi_target
from pipeline.helpers.util import json_loads, json_dumps


class PublishReportsAndStreams(luigi.Task):
    date = luigi.DateParameter()

    output_path = luigi.Parameter(default="/data/ooni/public/reports/json/")
    report_path = luigi.Parameter(default="/data/ooni/private/reports-raw/json/")

    bridge_db_path = luigi.Parameter(default="/data/ooni/private/bridge_reachability/bridge_db.json")

    def output(self):
        return get_luigi_target(
            os.path.join(self.output_path, "{}.json".format(self.date))
        )

    def _get_dst_path(self, entry):
        date = datetime.utcfromtimestamp(int(entry.get("start_time", 0)))
        date_string = date.isoformat().replace(":","").replace("-", "")+"Z"
        output_filename = "{date}-{probe_cc}-{asn}-{test_name}-{df_version}-{ext}".format(
            date=date_string,
            asn=entry["probe_asn"],
            probe_cc=entry["probe_cc"],
            test_name=entry["test_name"],
            df_version="v1",
            ext="probe.json.gz"
        )
        return os.path.join(
            self.output_path,
            date.strftime("%Y-%m-%d"),
            output_filename
        )

    def is_bridge_reachability(self, entry, bridge_db):
        if entry['test_name'] not in ["tcp_connect", "bridge_reachability"]:
            return False
        elif entry.get('input') and entry.get('input').strip() in bridge_db.keys():
            return True
        elif entry.get('bridge_address') and entry.get('bridge_address').strip() in bridge_db.keys():
            return True
        return False

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

    def publish_and_sanitise(self, report_file_path, stream_file, bridge_db):
        in_target = get_luigi_target(report_file_path)
        in_file = in_target.open('r')
        first_line = in_file.readline()

        if not first_line:
            in_file.close()
            return

        entry = json_loads(first_line.strip())
        dst_path = self._get_dst_path(entry)
        out_file = get_luigi_target(dst_path).open('w')

        if self.is_bridge_reachability(entry, bridge_db):
            if entry['test_name'] == 'tcp_connect':
                sanitise_function = self.sanitise_tcp_connect
            elif entry['test_name'] == 'bridge_reachability':
                sanitise_function = self.sanitise_bridge_reachability
            entry = sanitise_function(entry, bridge_db)
            out_file.write(json_dumps(entry))
            stream_file.write(json_dumps(entry))
            for line in in_file:
                entry = json_loads(line.strip())
                entry = sanitise_function(entry, bridge_db)
                out_file.write(json_dumps(entry))
                stream_file.write(json_dumps(entry))
        else:
            stream_file.write(first_line)
            out_file.write(first_line)
            for line in in_file:
                out_file.write(line)
                stream_file.write(line)
            out_file.close()
            in_file.close()

    def run(self):
        with get_luigi_target(self.bridge_db_path).open('r') as f:
            bridge_db = json.load(f)

        config = get_config()
        stream_file = self.output().open('w')

        for report_file_path in list_report_files(
            os.path.join(self.report_path, self.date.strftime("%Y-%m-%d")),
            aws_access_key_id=config.get('s3', 'aws_access_key_id'),
            aws_secret_access_key=config.get('s3', 'aws_secret_access_key'),
            report_extensions=(".json",)
        ):
            self.publish_and_sanitise(report_file_path, stream_file, bridge_db)
        stream_file.close()

class PublishReportsAndStreamsRange(luigi.Task):
    date_interval = luigi.DateParameter()

    output_path = luigi.Parameter(default="/data/ooni/public/reports/json/")
    report_path = luigi.Parameter(default="/data/ooni/private/reports-raw/json/")

    bridge_db_path = luigi.Parameter(default="/data/ooni/private/bridge_reachability/bridge_db.json")

    def requires(self):
        for date in self.date_interval:
            yield PublishReportsAndStreams(date=date,
                                           output_path=self.output_path,
                                           report_path=self.report_path,
                                           bridge_db_path=self.bridge_db_path)
