import argparse
import os
from pathlib import Path

from summary.core.SummaryFactory import SummaryFactory
from summary.lib.utils import logger_utils

logger = logger_utils.get_logger(__name__)
ROOT_DIR = os.path.dirname(os.path.abspath(__file__))


def build_output(output: Path):
    if not output:
        build_dir = Path(ROOT_DIR).parent / "build"
        os.makedirs(build_dir, exist_ok=True)
        return build_dir / "summary.json"

    return output


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
    output = build_output(args.output)
    SummaryFactory.get_summary(Path(args.report), args.type).parse(Path(output))


if __name__ == '__main__':
    run()
