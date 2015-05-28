from __future__ import absolute_import, print_function, unicode_literals

import os
import shutil
import logging

from dateutil.parser import parse as date_parse

import luigi
import luigi.worker
import luigi.hdfs
from luigi.task import ExternalTask
from luigi.format import GzipFormat
from luigi.s3 import S3Target
from luigi.file import LocalTarget

from pipeline.helpers.util import list_report_files

logger = logging.getLogger('ooni-pipeline')

class ReportSource(ExternalTask):
    src = luigi.Parameter()

    def output(self):
        file_format = None
        if self.src.endswith(".gz"):
            file_format = GzipFormat()
        if self.src.startswith("s3n://"):
            return S3Target(self.src, format=file_format)
        return LocalTarget(self.src, format=file_format)


class S3CopyRawReport(luigi.Task):
    src = luigi.Parameter()
    dst = luigi.Parameter()

    def requires(self):
        return ReportSource(self.src)

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
            uri = os.path.join(self.dst, date.strftime("%Y-%m-%d"), filename)
            return S3Target(uri)
        except Exception:
            return S3Target(os.path.join(self.dst, "failed",
                                         os.path.basename(self.src)))

    def run(self):
        with self.input().open('r') as in_file:
            with self.output().open('w') as out_file:
                shutil.copyfileobj(in_file, out_file)


def run(src_directory, dst, worker_processes, limit=None):
    sch = luigi.scheduler.CentralPlannerScheduler()
    idx = 0
    w = luigi.worker.Worker(scheduler=sch,
                            worker_processes=worker_processes)

    for filename in list_report_files(src_directory):
        if limit is not None and idx >= limit:
            break
        idx += 1
        logging.info("uploading %s" % filename)
        task = S3CopyRawReport(src=filename, dst=dst)
        w.add(task)
    w.run()
    w.stop()
