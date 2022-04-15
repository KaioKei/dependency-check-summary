from pathlib import Path
from typing import List, Optional

from summary.core.summary import SummaryParser
from summary.lib.utils import logger_utils
from summary.models.summary_model import Overview, Report, Severity, Summary

logger = logger_utils.get_logger(__name__)

# REPORT KEYS
ISSUES_KEY = "Issues"
SEVERITY_KEY = "severity"


class GosecSummary(SummaryParser):

    def parse(self, output: Optional[Path]) -> "None":
        logger.debug(f"parsing report into a summary")
        for issue in self.report.get(ISSUES_KEY):
            severity = Severity[str.upper(issue.get(SEVERITY_KEY))]
            self.update_count(severity)

        super().parse(output)
