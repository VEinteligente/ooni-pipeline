# -*- coding: utf-8 -*-
from __future__ import absolute_import, print_function, unicode_literals

import os
import logging

import luigi
import luigi.postgres
from luigi.contrib.spark import PySparkTask

from invoke.config import Config

from pipeline.helpers.util import json_loads, get_date_interval
from pipeline.helpers.util import json_dumps, get_luigi_target
from pipeline.helpers.util import get_imported_dates


config = Config(runtime_path="invoke.yaml")
logger = logging.getLogger('ooni-pipeline')


class CountInterestingReports(PySparkTask):
    driver_memory = '2g'
    executor_memory = '3g'
    py_packages = ["pipeline"]

    date = luigi.DateParameter()
    src = luigi.Parameter()
    dst = luigi.Parameter()

    def input(self):
        return get_luigi_target(os.path.join(self.src, "%s.json" % self.date))

    def output(self):
        return get_luigi_target(os.path.join(self.dst,
                                             "http_requests_test-interesting-%s.json" % self.date))

    def main(self, sc, *args):
        from pyspark.sql import SQLContext
        sqlContext = SQLContext(sc)
        df = sqlContext.jsonFile(self.input().path)
        http_requests = df.filter("test_name = 'http_requests_test' AND record_type = 'entry'")
        interestings = http_requests.filter("body_length_match = false OR headers_match = false").groupBy("report_id")

        out_file = self.output().open('w')
        for interesting in interestings.count().collect():
            data = json_dumps({
                "report_id": interesting.report_id,
                "count": interesting.count
            })
            out_file.write(data)
            out_file.write("\n")
        out_file.close()


class SparkResultsToDatabase(luigi.postgres.CopyToTable):
    src = luigi.Parameter()
    date = luigi.DateParameter()
    dst = luigi.Parameter()

    host = str(config.postgres.host)
    database = str(config.postgres.database)
    user = str(config.postgres.username)
    password = str(config.postgres.password)
    table = 'spark-results'

    columns = [
        ("report_id", "TEXT"),
        ("count", "INT")
    ]

    def requires(self):
        return CountInterestingReports(src=self.src, date=self.date, dst=self.dst)

    def rows(self):
        with self.input().open('r') as in_file:
            for line in in_file:
                record = json_loads(line.strip('\n'))
                logger.info("Looking at %s with count %s" % (record["report_id"], record["count"]))
                yield record["report_id"], record["count"]

def run(date_interval, src="s3n://ooni-public/reports-sanitised/streams/",
        dst="s3n://ooni-public/processed/", worker_processes=16):

    sch = luigi.scheduler.CentralPlannerScheduler()
    w = luigi.worker.Worker(scheduler=sch,
                            worker_processes=worker_processes)
    imported_dates = get_imported_dates(src,
                                        aws_access_key_id=config.aws.access_key_id,
                                        aws_secret_access_key=config.aws.secret_access_key)
    interval = get_date_interval(date_interval)
    for date in interval:
        if str(date) not in imported_dates:
            continue

        logger.info("Running CountInterestingReports for %s on %s to %s" %
                    (date, src, dst))
        task = SparkResultsToDatabase(src=src, date=date, dst=dst)
        w.add(task)

    w.run()
    w.stop()
