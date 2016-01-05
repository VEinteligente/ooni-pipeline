import os
import json

from datetime import datetime

import luigi

from luigi.configuration import get_config

from pipeline.helpers.util import list_report_files, get_luigi_target
from pipeline.helpers.util import json_loads


class PublishReports(luigi.Task):
    date_interval = luigi.DateIntervalParameter()

    output_path = luigi.Parameter(default="/data/ooni/public/reports/json/")
    report_path = luigi.Parameter(default="/data/ooni/private/reports-raw/json/")

    bridge_db_path = luigi.Parameter(default="/data/ooni/private/bridge_reachability/bridge_db.json")

    def output(self):
        return os.path.join(self.output_path,
                            "publish-log-{}.txt".format(self.date_interval))

    def _get_dst_path(self, entry):
        date_string = datetime.utcfromtimestamp(entry.get("start_time", 0))
        date_string = date_string.isoformat().replace(":","")+"Z"
        output_filename = "{date}-{probe_cc}-{asn}-{test_name}-{df_version}-{ext}".format(
            date=date_string,
            asn=entry["probe_asn"],
            probe_cc=entry["probe_asn"],
            test_name=entry["test_name"],
            df_version="v1",
            ext="probe.json.gz"
        )
        return os.path.join(self.output_path, output_filename)

    def is_bridge_reachability(self, entry, bridge_db):
        if entry['test_name'] not in ["tcp_connect", "bridge_reachability"]:
            return False
        elif entry.get('input', '').strip() in bridge_db.keys():
            return True
        elif entry.get('bridge_address', '').strip() in bridge_db.keys():
            return True
        return False

    def publish(self, report_file_path, publish_log, bridge_db):
        in_file = get_luigi_target(report_file_path).open('r')
        first_line = in_file.readline()
        entry = json_loads(first_line.strip())

        if self.is_bridge_reachability(entry):
            return

        dst_path = self._get_dst_path(entry)
        out_file = get_luigi_target(dst_path).open('w')
        out_file.write(first_line)
        for line in in_file:
            out_file.write(line)
        out_file.close()
        in_file.close()
        in_file.remove()
        publish_log.write(
            "%s: %s \n".format(datetime.now().isoformat(), dst_path)
        )

    def run(self):
        with get_luigi_target(self.bridge_db_path).open('r') as f:
            bridge_db = json.load(f)

        config = get_config()
        publish_log = self.output().open('w')

        for date in self.date_interval:
            for report_file_path in list_report_files(
                os.path.join(self.report_path, date.strftime("%Y-%m-%d")),
                aws_access_key_id=config.get('s3', 'aws_access_key_id'),
                aws_secret_access_key=config.get('s3', 'aws_secret_access_key'),
                report_extensions=(".json", ".yaml")
            ):
                self.publish(report_file_path, publish_log, bridge_db)
        publish_log.close()
