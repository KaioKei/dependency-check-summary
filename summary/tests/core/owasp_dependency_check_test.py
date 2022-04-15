import os
from pathlib import Path

from summary.core.owasp_dependency_check import OwaspDependencyCheckSummary
from summary.lib.utils import file_utils

THIS_DIR = os.path.dirname(os.path.abspath(__file__))


def test_parse():
    output_dir = Path("/tmp/dependency-check-summary/test/build/owasp-dependency-check")
    os.makedirs(output_dir, exist_ok=True)
    output = Path(output_dir, "report.json")
    input_test_file = os.path.join(THIS_DIR, os.pardir, "resources/owasp_dependency_check/verify.json")
    test_input_dict = file_utils.read_json(Path(input_test_file))
    input_report = os.path.join(THIS_DIR, os.pardir, test_input_dict.get("input"))
    total_expected = test_input_dict.get("total")

    OwaspDependencyCheckSummary(Path(input_report)).parse(output)

    report_dict = file_utils.read_json(output)
    total = report_dict.get("overview").get("total")
    assert total == total_expected
