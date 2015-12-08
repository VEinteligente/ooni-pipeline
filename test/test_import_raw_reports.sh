#!/bin/sh
luigi --local-scheduler --module pipeline ImportRawReportDirectory --src-dir test/fixtures/ooni-incoming --dst test/fixtures/ooni-private/reports-raw/yaml/
