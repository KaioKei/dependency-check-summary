from summary.models.summary_model import Severity


def test_get_highest_severity():
    severity_low = Severity.LOW
    severity_medium = Severity.MEDIUM
    severity_high = Severity.HIGH
    severity_critical = Severity.CRITICAL

    assert SummaryParser.get_highest_severity(severity_low, severity_medium) == severity_medium
    assert SummaryParser.get_highest_severity(severity_low, severity_high) == severity_high
    assert SummaryParser.get_highest_severity(severity_low, severity_critical) == severity_critical

    assert SummaryParser.get_highest_severity(severity_medium, severity_high) == severity_high
    assert SummaryParser.get_highest_severity(severity_medium,
                                              severity_critical) == severity_critical

    assert SummaryParser.get_highest_severity(severity_high, severity_critical) == severity_critical

    assert SummaryParser.get_highest_severity(severity_low, severity_low) == severity_low
    assert SummaryParser.get_highest_severity(severity_medium, severity_medium) == severity_medium
    assert SummaryParser.get_highest_severity(severity_high, severity_high) == severity_high
    assert SummaryParser.get_highest_severity(severity_critical,
                                              severity_critical) == severity_critical
