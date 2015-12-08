from __future__ import absolute_import, print_function, unicode_literals

import os
import shutil
import logging

from dateutil.parser import parse as date_parse

import luigi
import luigi.worker
import luigi.hdfs
from luigi.configuration import get_config

from pipeline.helpers.util import list_report_files, get_luigi_target

config = get_config()
logger = logging.getLogger('luigi-interface')


class ImportRawReport(luigi.Task):
    src = luigi.Parameter()
    dst = luigi.Parameter()
    move = luigi.BoolParameter()

    def input(self):
        return get_luigi_target(self.src)

    def output(self):
        try:
            parts = os.path.basename(self.src).split("-")
            ext = parts[-1]
            # XXX this parsing stuff is insane...
            if ext.startswith("probe") or \
                    ext.startswith("backend"):
                date = date_parse('-'.join(parts[-5:-2]))
                asn = parts[-2]
                test_name = '-'.join(parts[:-5])
            elif parts[0].startswith("report"):
                date = date_parse('-'.join(parts[-3:-1]+parts[-1].split(".")[:1]))
                asn = "ASX"
                test_name = '-'.join(parts[1:-3])
                ext = "probe."+'.'.join(parts[-1].split(".")[1:])
            else:
                date = date_parse('-'.join(parts[-4:-1]))
                asn = parts[-1].split(".")[0]
                ext = "probe."+'.'.join(parts[-1].split(".")[1:])
                test_name = '-'.join(parts[:-4])
            # To facilitate sorting and splitting around "-" we convert the
            # date to be something like: 20150101T000015Z
            timestamp = date.strftime("%Y%m%dT%H%M%SZ")
            filename = "{date}-{asn}-{test_name}-{df_version}-{ext}".format(
                date=timestamp,
                asn=asn,
                test_name=test_name,
                df_version="v1",
                ext=ext.replace(".gz", "").replace(".yamloo", ".yaml")
            )
            uri = os.path.join(self.dst, date.strftime("%Y"),
                               date.strftime("%m-%d"), filename)
            return get_luigi_target(uri)
        except Exception as exc:
            logger.error(exc)
            logger.error("Failed to import %s" % self.src)
            failed_uri = os.path.join(self.dst, "failed",
                                      os.path.basename(self.src))
            return get_luigi_target(failed_uri)

    def run(self):
        input = self.input()
        output = self.output()
        with output.open('w') as out_file:
            with input.open('r') as in_file:
                shutil.copyfileobj(in_file, out_file)
        if self.move:
            input.remove()


class ImportRawReportDirectory(luigi.Task):
    incoming_dir = luigi.Parameter()
    private_dir = luigi.Parameter()
    move = luigi.BoolParameter(default=False)

    def output(self):
        uri = os.path.join(self.private_dir, 'import.log')
        return get_luigi_target(uri)

    def run(self):
        output = self.output()
        out_file = output.open('w')
        for filename in list_report_files(self.incoming_dir,
                                          aws_access_key_id=config.get('aws', 'access-key-id'),
                                          aws_secret_access_key=config.get('aws', 'secret-access-key')):
            t = ImportRawReport(filename, os.path.join(self.private_dir,
                                                       'reports-raw',
                                                       'yaml'), self.move)
            #imported_date = '-'.join(path.split('/')[-3:-1])
            yield t
            out_file.write("%s\n" % t.output().path)
        out_file.close()
