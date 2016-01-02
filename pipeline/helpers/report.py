from __future__ import absolute_import, print_function, unicode_literals

import os
import sys
import time
import random
import string
import logging
import traceback

from base64 import b64encode

from datetime import datetime

import yaml
# dns_consistency tests use [8.8.8.8, 53] as key in a dict
def construct_yaml_map(loader, node):
    pairs = [(str(key) if isinstance(key, list) else key, value)
            for (key, value) in loader.construct_pairs(node, deep=True)]
    return dict(pairs)
yaml.SafeLoader.add_constructor(u'tag:yaml.org,2002:map', construct_yaml_map)
from pipeline.helpers import sanitise

logger = logging.getLogger('ooni-pipeline')

header_avro = {
    "type": "record",
    "name": "ReportHeader",
    "fields": [
        {"name": "backend_version", "type": "string"},
        {"name": "input_hashes", "type": "array", "items": "string"},
        {"name": "options", "type": "string"},
        {"name": "probe_asn", "type": "string"},
        {"name": "probe_cc", "type": "string"},
        {"name": "probe_ip", "type": "string"},
        {"name": "record_type", "type": "string"},
        {"name": "report_filename", "type": "string"},
        {"name": "report_id", "type": "string"},
        {"name": "software_name", "type": "string"},
        {"name": "software_version", "type": "string"},
        {"name": "start_time", "type": "string"},
        {"name": "test_name", "type": "string"},
        {"name": "test_version", "type": "string"},
        {"name": "data_format_version", "type": "string"},
        {"name": "test_helpers", "type": "string"}
    ]
}

class YAMLReport(object):
    def __init__(self, in_file, path):
        self._start_time = time.time()
        self._end_time = None
        self._skipped_line = 0

        self.in_file = in_file
        self.path = path
        self.filename = os.path.basename(path)
        self._report = yaml.safe_load_all(self.in_file)
        self.process_header(self._report)

    def _restart_from_line(self, line_number):
        """
        This is used to skip to the specified line number in case of YAML
        parsing erorrs. We also add to self._skipped_line since the YAML parsed
        will consider the line count as relative to the start of the document.
        """
        self._skipped_line = line_number+self._skipped_line+1
        self.in_file.seek(0)
        for _ in xrange(self._skipped_line):
            self.in_file.readline()
        self._report = yaml.safe_load_all(self.in_file)

    def process_entry(self, entry):
        if 'report' in entry:
            entry.update(entry.pop('report'))
        entry.update(self.header)
        return entry

    def entries(self):
        while True:
            try:
                entry = self._report.next()
                if not entry:
                    continue
                yield self.process_entry(entry)
            except StopIteration:
                break
            except Exception as exc:
                if hasattr(exc, 'problem_mark'):
                    self._restart_from_line(exc.problem_mark.line)
                else:
                    self._end_time = time.time()
                    print("failed to process the entry for %s" % self.filename)
                    print(traceback.format_exc())
                    raise exc
                continue
        self._end_time = time.time()

    @property
    def header(self):
        return self._raw_header

    def get_filename(self):
        return self.filename

    def process_header(self, report):
        try:
            self._raw_header = report.next()
        except StopIteration:
            return

        self.report_date = datetime.fromtimestamp(self._raw_header["start_time"])
        date = self.report_date.strftime("%Y-%m-%d")
        if not self._raw_header.get("report_id"):
            nonce = ''.join(random.choice(string.ascii_lowercase)
                            for x in xrange(40))
            self._raw_header["report_id"] = date + nonce

        self._raw_header["report_filename"] = self.get_filename()

class JSONReport(YAMLReport):
    def base64_binary_data(self, entry):
        def is_binary(s):
            PY3 = sys.version_info[0] == 3
            int2byte = (lambda x: bytes((x,))) if PY3 else chr

            text_characters = "".join(map(chr, range(32, 127)) + list("\n\r\t\b"))

            if b'\x00' in s:
                return True
            elif not s:
                return False

            t = s.translate(None, str(text_characters))

            # If more than 30% non-text characters, then
            # we consider it to be binary
            if float(len(t))/len(s) > 0.30:
                return True
            return False

        def fix_function(data):
            if isinstance(data, str):
                if is_binary(data):
                    return {
                        "data": b64encode(data),
                        "encoding": "base64"
                    }
            return data

        def traverse_and_fix(data):
            if isinstance(data, dict):
                new = data.copy()
                for k, v in data.copy().items():
                    if not isinstance(k, str):
                        k = str(k)
                    new[k] = traverse_and_fix(v)
                return new
            elif isinstance(data, list):
                new = []
                for item in data:
                    new.append(traverse_and_fix(item))
                return new
            else:
                return fix_function(data)

        return traverse_and_fix(entry)

    def process_entry(self, entry):
        entry = YAMLReport.process_entry(self, entry)
        entry = self.base64_binary_data(entry)
        return entry

class SanitisedReport(YAMLReport):
    def __init__(self, in_file, bridge_db, path):
        self.bridge_db = bridge_db
        super(SanitisedReport, self).__init__(in_file, path)

    def entries(self):
        yield self.header['sanitised'], self.header['raw']
        for sanitised_report, raw_report in self.process():
            yield sanitised_report, raw_report
        yield self.footer['sanitised'], self.footer['raw']

    def sanitise_entry(self, entry):
        # XXX we probably want to ignore these sorts of tests
        if not self.header.get('test_name'):
            logger.error("test_name is missing in %s" % entry["report_id"])
            return entry
        return sanitise.run(self.header['test_name'], entry, self.bridge_db)

    def add_record_type(self, entry):
        entry["record_type"] = "entry"
        return entry

    def process_entry(self, entry):
        if 'report' in entry:
            entry.update(entry.pop('report'))
        raw_entry = entry.copy()
        sanitised_entry = entry.copy()

        raw_entry.update(self._raw_header)
        sanitised_entry.update(self._sanitised_header)

        raw_entry = self.add_record_type(raw_entry)
        sanitised_entry = self.add_record_type(sanitised_entry)

        sanitised_entry = self.sanitise_entry(sanitised_entry)
        return sanitised_entry, raw_entry

    @property
    def footer(self):
        raw = self._raw_header.copy()
        sanitised = self._sanitised_header.copy()

        process_time = None
        if self._end_time:
            process_time = self._end_time - self._start_time

        extra_keys = {
            'record_type': 'footer',
            'stage_1_process_time': process_time
        }

        raw.update(extra_keys)
        sanitised.update(extra_keys)

        return {
            "raw": raw,
            "sanitised": sanitised
        }
