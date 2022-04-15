import sys
from enum import Enum
from pathlib import Path

from summary.core.gosec import GosecSummary
from summary.core.owasp_dependency_check import OwaspDependencyCheckSummary
from summary.lib.utils import logger_utils

logger = logger_utils.get_logger(__name__)


class SummaryType(str, Enum):
    OWASP_DEPENDENCY_CHECK = "owasp-dependency-check"
    GOSEC = "gosec"


class SummaryFactory:

    @staticmethod
    def get_summary(report_path: Path, summary_type: str):
        if summary_type == SummaryType.OWASP_DEPENDENCY_CHECK.value:
            return OwaspDependencyCheckSummary(report_path)
        elif summary_type == SummaryType.GOSEC.value:
            return GosecSummary(report_path)
        else:
            logger.fatal(f"Unsupported summary type: {summary_type}\n"
                         f"Supported types are: {[x.value for x in SummaryType]}")
            sys.exit(1)
