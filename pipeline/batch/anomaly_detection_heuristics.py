import os
from datetime import datetime

import luigi
from pipeline.helpers.util import get_luigi_target
from pipeline.helpers.util import json_dumps, json_loads
from .list_reports import ListReportFiles

class DetectAnomalousReports(luigi.Task):
    test_name = ""
    date_interval = luigi.DateIntervalParameter()

    output_path = luigi.Parameter(default="/data/ooni/working-dir")
    report_path = luigi.Parameter(default="/data/ooni/public/reports-sanitised/json/")

    def requires(self):
        return ListReportFiles(date_interval=self.date_interval,
                               test_names=[self.test_name],
                               output_path=self.output_path,
                               report_path=self.report_path)

    def output(self):
        path = os.path.join(
            self.output_path,
            "anomalous-{}-{}.json".format(self.test_name, self.date_interval)
        )
        return get_luigi_target(path)

    def run(self):
        out_file = self.output().open('w')
        in_file = self.input().open('r')
        for file_path in in_file:
            offset = 0
            file_path = file_path.strip()
            report_file = get_luigi_target(file_path).open('r')
            for line in report_file:
                measurement = json_loads(line.strip())
                anomaly = self.detect_anomaly(measurement)
                if anomaly is not False:
                    date_string = datetime.utcfromtimestamp(int(measurement.get("start_time", 0)))
                    date_string = date_string.isoformat().replace(":","").replace("-", "")+"Z"
                    entry = {
                        "input": measurement.get("input"),
                        "report_id": measurement.get("report_id"),
                        "probe_cc": measurement.get("probe_cc"),
                        "probe_asn": measurement.get("probe_asn"),
                        "date": date_string,
                        "anomaly": anomaly,
                        "report_path": file_path,
                        "file_offset": offset
                    }
                    entry.update(self.extra_keys(measurement))
                    out_file.write(json_dumps(entry))
                    out_file.write("\n")
                offset += 1
        out_file.close()
        in_file.close()

class DetectAnomalousHTTPInvalidRequestLine(DetectAnomalousReports):
    test_name = "http_invalid_request_line"

    def detect_anomaly(self, measurement):
        if measurement.get("tampering") == False:
            return False
        if all(_ == "" for _ in measurement.get("received")):
            return "empty_response"
        else:
            return "inconsistent_response"

    def extra_keys(self, measurement):
        return {
            "received": measurement.get("received")
        }

class DetectAnomalousHTTPHeaderFieldManipulation(DetectAnomalousReports):
    test_name = "http_header_field_manipulation"

    def detect_anomaly(self, measurement):
        if all(v == False for k, v in measurement.get("tampering", {}).items()):
            return False
        if any(v == True for k, v in measurement.get("tampering", {}).items()):
            return "tampering"
        return False

    def extra_keys(self, measurement):
        return {
            "tampering": measurement.get("tampering")
        }

class DetectAnomalousDNSConsistency(DetectAnomalousReports):
    test_name = "dns_consistency"

    def detect_anomaly(self, measurement):
        return any(_ == True for _ in measurement.get("tampering"))

    def extra_keys(self, measurement):
        tampered_resolvers = []
        tampered_queries = {}
        for resolver_ip, tampering in measurement.get("tampering", {}).items():
            if tampering == True:
                tampered_resolvers.append(resolver_ip)
        for query in measurement.get('queries', []):
            if query.get("resolver", []).get(0, "") in tampered_resolvers:
                tampered_queries[query['resolver'][0]] = query.get('addrs', [])
        return {
            "tampered_resolvers": tampered_resolvers,
            "tampered_queries": tampered_queries
        }

class BlockPagedetector(object):
    known_blockpages = {
        "SA": '<title>Blocked',
        "IR": 'iframe src="http://10.10"'
    }
    def detect(self, body, cc):
        blockpage_string = self.known_blockpages.get(cc)
        if not blockpage_string:
            return False
        if blockpage_string in body:
            return True
        return False

class DetectAnomalousHTTPRequests(DetectAnomalousReports):
    test_name = "http_requests"

    def detect_anomaly(self, measurement):
        bpd = BlockPagedetector()
        def is_cloudflare(requests):
            for request in requests:
                if 'Attention Required! | CloudFlare' in request.get("response", {}).get("body", ""):
                    return True
            return False

        experiment_requests = []
        control_requests = []

        for request in measurement.get("requests"):
            if request.get("tor", {}).get("is_tor") is True:
                control_requests.append(request)
            elif request.get("tor") is True:
                control_requests.append(request)
            elif request.get("url").startswith("shttp://"):
                control_requests.append(request)
            else:
                experiment_requests.append(request)
        for request in experiment_requests:
            if bpd.detect(request.get('response', {}).get('body', "")):
                return 'blockpage_detected'

        if measurement.get("control_failure") != None \
                and measurement.get("experiment_failure") == None:
            return 'control_failure'
        if measurement.get("body_length_match") == False:
            if is_cloudflare(measurement.get("requests")):
                return 'cloudflare'
            else:
                return 'body_length_mismatch'

        return False

    def extra_keys(self, measurement):
        return {
            "body_proportion": measurement.get("body_proportion")
        }

class DetectAllAnomalies(luigi.WrapperTask):
    date_interval = luigi.DateIntervalParameter()

    output_path = luigi.Parameter(default="/data/ooni/working-dir")
    report_path = luigi.Parameter(default="/data/ooni/public/reports-sanitised/json/")

    def requires(self):
        yield DetectAnomalousHTTPInvalidRequestLine(
            date_interval=self.date_interval,
            output_path=self.output_path,
            report_path=self.report_path
        )
        yield DetectAnomalousHTTPHeaderFieldManipulation(
            date_interval=self.date_interval,
            output_path=self.output_path,
            report_path=self.report_path
        )
        yield DetectAnomalousDNSConsistency(
            date_interval=self.date_interval,
            output_path=self.output_path,
            report_path=self.report_path
        )
        yield DetectAnomalousHTTPRequests(
            date_interval=self.date_interval,
            output_path=self.output_path,
            report_path=self.report_path
        )
