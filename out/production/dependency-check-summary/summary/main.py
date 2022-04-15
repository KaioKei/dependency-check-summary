import argparse
import sys

from summary.core.summary import SummaryParser
from summary.lib.exceptions.file_exceptions import NotAJsonFormat
from summary.lib.utils import file_utils, logger_utils
from summary.models.summary_model import Criticality

logger = logger_utils.get_logger(__name__)


def parse_arguments(parser: argparse.ArgumentParser):
    parser.add_argument('-f', '--file', dest='report', action='store', required=True,
                        help='Path to the dependency-check JSON report file.')
    return parser.parse_args()


def run():
    args = parse_arguments(argparse.ArgumentParser())

    report_path = args.report
    try:
        report_content = file_utils.read_json(report_path)
        summary = SummaryParser(report_content).parse()
    except NotAJsonFormat:
        logger.fatal(f"Expected a JSON report, got '{report_path}' instead")
        sys.exit(1)

    logger.info("hello world !")


if __name__ == '__main__':
    run()
