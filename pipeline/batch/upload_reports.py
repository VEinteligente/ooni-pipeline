from __future__ import absolute_import, print_function, unicode_literals

import os
import shutil
import logging

from dateutil.parser import parse as date_parse

import luigi
import luigi.worker
import luigi.hdfs
from luigi.task import ExternalTask
from luigi.configuration import get_config

from pipeline.helpers.util import list_report_files, get_luigi_target

config = get_config()
logger = logging.getLogger('luigi-interface')


class ReportSource(ExternalTask):
    src = luigi.Parameter()

    def output(self):
        return get_luigi_target(self.src)

class ImportRawReport(luigi.Task):
    src = luigi.Parameter()
    dst = luigi.Parameter()
    move = luigi.Parameter()

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
    src_dir = luigi.Parameter()
    dst = luigi.Parameter()
    move = luigi.Parameter(default=False)

    def requires(self):
        return [
            ImportRawReport(filename, self.dst, self.move)
                    for filename in list_report_files(self.src_dir,
                                                      aws_access_key_id=config.get('aws', 'access-key-id'),
                                                      aws_secret_access_key=config.get('aws', 'secret-access-key')
                                                      )
                ]

def run(src_directory, dst, worker_processes, limit=None, move=False):
    sch = luigi.scheduler.CentralPlannerScheduler()
    idx = 0
    w = luigi.worker.Worker(scheduler=sch,
                            worker_processes=worker_processes)

    uploaded_files = []
    for filename in list_report_files(
        src_directory, aws_access_key_id=config.get('aws', 'access_key_id'),
            aws_secret_access_key=config('aws', 'secret_access_key')):
        if limit is not None and idx >= limit:
            break
        idx += 1
        logging.info("uploading %s" % filename)
        task = ImportRawReport(src=filename, dst=dst, move=move)
        uploaded_files.append(task.output().path)
        w.add(task, multiprocess=True)
    w.run()
    w.stop()
    uploaded_dates = []
    for uploaded_file in uploaded_files:
        uploaded_date = os.path.basename(os.path.dirname(uploaded_file))
        if uploaded_date not in uploaded_dates:
            uploaded_dates.append(uploaded_date)
    return uploaded_dates
