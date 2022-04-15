import json
import os
import sys
from pathlib import Path
from typing import Dict, List, Optional

from summary.lib.exceptions.file_exceptions import NotAJsonFormat
from summary.lib.utils import file_utils, logger_utils
from summary.models.summary_model import Criticality, Overview, Report, Severity, Summary

logger = logger_utils.get_logger(__name__)

DEFAULT_OUTPUT_DIR = "build"
DEFAULT_REPORT_NAME = "summary.json"


class SummaryParser(object):
    summary: Summary
    output: Path
    reports: List[Report] = []
    total = 0
    critical_count = 0
    high_count = 0
    medium_count = 0
    low_count = 0
    uncategorized = 0

    def __init__(self, report: Path):
        """
        :param report: Content of the JSON report
        """
        self.path = report
        self.report = SummaryParser.read_report(report)

    @staticmethod
    def read_report(report: Path) -> "Dict":
        try:
            return file_utils.read_json(report)
        except NotAJsonFormat:
            logger.fatal(f"Expected a JSON report, got '{report}' instead")
            sys.exit(1)

    def update_count(self, severity: Severity):
        self.total += 1
        if Severity.LOW == severity:
            self.low_count += 1
        elif Severity.MEDIUM == severity:
            self.medium_count += 1
        elif Severity.HIGH == severity:
            self.high_count += 1
        elif Severity.CRITICAL == severity:
            self.critical_count += 1
        else:
            self.uncategorized += 1

    @staticmethod
    def get_highest_severity(highest: Severity, other_severity: Severity) -> "Severity":
        """
        Compare the current highest severity and the given severity to deduce the highest by
        criticality
        :param highest: current highest severity of package vulnerabilities
        :param other_severity: a given severity
        :return: The highest Severity
        """
        if Criticality[highest.value].value >= Criticality[other_severity.value].value:
            return highest
        else:
            return other_severity

    def write(self, output: Optional[Path]) -> "None":
        if not output:
            default_output_name = os.path.basename(self.path).split('.')[0]
            summary_output_dir = output if output else Path(DEFAULT_OUTPUT_DIR, default_output_name)
            os.makedirs(summary_output_dir, exist_ok=True)
            self.output = summary_output_dir / DEFAULT_REPORT_NAME
        else:
            self.output = output
        with open(self.output, 'w') as f:
            json.dump(self.summary.dict(), f)

    def parse(self, output: Optional[Path]) -> "None":
        """
        Override this method to build:
        - vulnerabilities models
        - reports models

        and call 'update_count' and super() to parse the input report.
        """
        overview = Overview(total=self.total,
                            critical=self.critical_count,
                            high=self.high_count,
                            medium=self.medium_count,
                            low=self.low_count,
                            uncategorized=self.uncategorized)

        self.summary = Summary(overview=overview, reports=self.reports)
        self.write(output)
        logger.info(f"Summary file: {self.output.absolute()}")
        logger.info(overview)
