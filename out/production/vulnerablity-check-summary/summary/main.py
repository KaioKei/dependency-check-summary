import argparse

from summary.core.summary import SummaryParser
from summary.lib.utils import logger_utils

logger = logger_utils.get_logger(__name__)




def parse_arguments(parser: argparse.ArgumentParser):
    parser.add_argument('-t', '--type', dest='type', action='store', required=True,
                        help='Source type of the report. Supported types are '
                             '"owasp-dependency-check" and "gosec"')
    parser.add_argument('-f', '--file', dest='report', action='store', required=True,
                        help='Path to the dependency-check JSON report file.')
    parser.add_argument('-o', '--output', dest='output', action='store',
                        help='Output path for the summary')
    return parser.parse_args()


def run():
    args = parse_arguments(argparse.ArgumentParser())

    report_path = args.report
    if args.type == Type.OWASP_DEPENDENCY_CHECK:
        OwaspDependencyCheckSummary(report_path).parse(args.output)
    elif args.type == Type.GOSEC:
        pass


if __name__ == '__main__':
    run()
