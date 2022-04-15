

class SummaryType(Enum, str):
    OWASP_DEPENDENCY_CHECK = "owasp-dependency-check"
    GOSEC = "gosec"

class SummaryFactory:

    @staticmethod
    def getSummary(report_path: Path, type: SummaryType) -> "Summary":
        if type == SummaryType.OWASP_DEPENDENCY_CHECK:
            return OwaspDependencyCheckSummary(report_path)
        elif type == SummaryType.OWASP_DEPENDENCY_CHECK:
            return GosecSummary(report_path)