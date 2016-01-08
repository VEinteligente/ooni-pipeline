import os
import datetime

import luigi
from pipeline.helpers.util import get_luigi_target
from pipeline.helpers.util import json_dumps, json_loads
from .list_reports import ListReportFiles

class DetectAnomalousReports(luigi.Task):
    test_name = ""
    date = luigi.DateParameter(default=datetime.date.today())

    output_path = luigi.Parameter(default="/data/ooni/working-dir")
    report_path = luigi.Parameter(default="/data/ooni/public/reports/json/")

    def requires(self):
        return ListReportFiles(date=self.date,
                               test_names=[self.test_name],
                               output_path=self.output_path,
                               report_path=self.report_path)

    def output(self):
        path = os.path.join(
            self.output_path,
            "anomalies",
            "anomalous-{}-{}.tsv".format(self.test_name, self.date)
        )
        return get_luigi_target(path)

    def run(self):
        out_file = self.output().open('w')
        in_file = self.input().open('r')
        for file_path in in_file:
            file_path = file_path.strip()
            report_file = get_luigi_target(file_path).open('r')
            for line in report_file:
                measurement = json_loads(line.strip())
                anomaly = self.detect_anomaly(measurement)
                date_string = datetime.datetime.utcfromtimestamp(int(measurement.get("start_time", 0)))
                date_string = date_string.isoformat().replace(":","").replace("-", "")+"Z"
                row = [
                    measurement.get("input"),
                    measurement.get("report_id"),
                    measurement.get("probe_cc"),
                    measurement.get("probe_asn"),
                    date_string,
                    anomaly
                ]
                row += self.extra_fields(measurement)
                row = map(lambda _: "none" if _ is None else _, row)
                out_file.write(
                    "{}\n".format("\t".join(row))
                )
        out_file.close()
        in_file.close()

class DetectAnomalousHTTPInvalidRequestLine(DetectAnomalousReports):
    test_name = "http_invalid_request_line"

    def detect_anomaly(self, measurement):
        if measurement.get("tampering") == False:
            return "none"
        if all(_ == "" for _ in measurement.get("received")):
            return "empty_response"
        else:
            return "inconsistent_response"

    def extra_fields(self, measurement):
        return [
            measurement.get("received")
        ]

class DetectAnomalousHTTPHeaderFieldManipulation(DetectAnomalousReports):
    test_name = "http_header_field_manipulation"

    def detect_anomaly(self, measurement):
        if all(v == False for k, v in measurement.get("tampering", {}).items()):
            return "none"
        if any(v == True for k, v in measurement.get("tampering", {}).items()):
            return "tampering"
        return "none"

    def extra_fields(self, measurement):
        return [
            measurement.get("tampering")
        ]

class DetectAnomalousDNSConsistency(DetectAnomalousReports):
    test_name = "dns_consistency"

    def detect_anomaly(self, measurement):
        return any(_ == True for _ in measurement.get("tampering"))

    def extra_fields(self, measurement):
        tampered_resolvers = []
        tampered_queries = {}
        for resolver_ip, tampering in measurement.get("tampering", {}).items():
            if tampering == True:
                tampered_resolvers.append(resolver_ip)
        for query in measurement.get('queries', []):
            if query.get("resolver") and query.get("resolver")[0] in tampered_resolvers:
                tampered_queries[query['resolver'][0]] = query.get('addrs', [])

        return [
            tampered_resolvers,
            tampered_queries
        ]

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

        for request in measurement.get("requests", []):
            if request.get("tor", {}).get("is_tor") is True:
                control_requests.append(request)
            elif request.get("tor") is True:
                control_requests.append(request)
            elif request["request"].get("url").startswith("shttp://"):
                control_requests.append(request)
            else:
                experiment_requests.append(request)
        for request in experiment_requests:
            if bpd.detect(request.get('response', {}).get('body', ""), measurement['probe_cc']):
                return 'blockpage_detected'

        if measurement.get("control_failure") == None \
                and measurement.get("experiment_failure") != None:
            return 'experiment_failure'
        if measurement.get("body_length_match") == False:
            if is_cloudflare(measurement.get("requests")):
                return 'cloudflare'
            else:
                return 'body_length_mismatch'

        return "none"

    def extra_fields(self, measurement):
        return [
            measurement.get("experiment_failure")
        ]

class DetectAllAnomalies(luigi.WrapperTask):
    date_interval = luigi.DateIntervalParameter()

    output_path = luigi.Parameter(default="/data/ooni/working-dir")
    report_path = luigi.Parameter(default="/data/ooni/public/reports/json/")

    def requires(self):
        for date in self.date_interval:
            yield DetectAnomalousHTTPInvalidRequestLine(
                date=date,
                output_path=self.output_path,
                report_path=self.report_path
            )
            yield DetectAnomalousHTTPHeaderFieldManipulation(
                date=date,
                output_path=self.output_path,
                report_path=self.report_path
            )
            yield DetectAnomalousDNSConsistency(
                date=date,
                output_path=self.output_path,
                report_path=self.report_path
            )
            yield DetectAnomalousHTTPRequests(
                date=date,
                output_path=self.output_path,
                report_path=self.report_path
            )

class CountCensoredSites(luigi.Task):
    date = luigi.DateParameter()

    output_path = luigi.Parameter(default="/data/ooni/working-dir")
    report_path = luigi.Parameter(default="/data/ooni/public/reports/json/")

    def requires(self):
        return DetectAnomalousHTTPRequests(date=self.date,
                                           output_path=self.output_path,
                                           report_path=self.report_path)

    def output(self):
        return {
            "count": get_luigi_target(os.path.join(
                self.output_path,
                "counts",
                "censored-sites-count-{}.tsv".format(self.date)
            )),
            "site-list": get_luigi_target(os.path.join(
                self.output_path,
                "counts",
                "site-list-{}.tsv".format(self.date)
            ))
        }

    def run(self):
        sites = set()
        censored_site_count = {}
        with self.input().open('r') as in_file:
            for line in in_file:
                url, report_id, probe_cc, \
                    probe_asn, date_string, anomaly, \
                    experiment_failure = line.strip().split("\t")
                sites.add(url)
                censored_site_count[report_id] = \
                    censored_site_count.get(report_id, {
                        "cc": probe_cc,
                        "asn": probe_asn,
                        "date": date_string
                    })
                censored_site_count[report_id][anomaly+"-count"] = \
                    censored_site_count[report_id].get(anomaly+"-count", 0) + 1

        with self.output()['site-list'].open('w') as site_list:
            for site in sites:
                site_list.write(site+"\n")

        with self.output()['count'].open('w') as counts:
            for report_id, value in censored_site_count.items():
                counts.write("{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}\n".format(
                    report_id, value['cc'], value['asn'], value['date'],
                    value.get('blockpage_detected-count', 0),
                    value.get('experiment_failure-count', 0),
                    value.get('body_length_mismatch-count', 0),
                    value.get('none-count', 0),
                ))

class AggregateCensoredSitesCount(luigi.WrapperTask):
    date_interval = luigi.DateIntervalParameter()

    output_path = luigi.Parameter(default="/data/ooni/working-dir")
    report_path = luigi.Parameter(default="/data/ooni/public/reports/json/")

    def requires(self):
        for date in self.date_interval:
            yield CountCensoredSites(date=date, output_path=self.output_path,
                                     report_path=self.report_path)
