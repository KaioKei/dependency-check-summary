from pathlib import Path
from typing import Dict, List, Optional, Set

from summary.core.summary import SummaryParser
from summary.lib.utils import logger_utils
from summary.models.summary_model import Overview, Report, Severity, Summary, Vulnerability

logger = logger_utils.get_logger(__name__)

ID_KEY = "id"
DEPENDENCIES_KEY = "dependencies"
DESCRIPTION_KEY = "description"
FILE_NAME_KEY = "fileName"
NAME_KEY = "name"
PACKAGES_KEY = "packages"
SEVERITY_KEY = "severity"
SOFTWARE_KEY = "software"
VULNERABILITY_IDS_KEY = "vulnerabilityIds"
VULNERABILITIES_KEY = "vulnerabilities"
VULNERABLE_SOFTWARE_KEY = "vulnerableSoftware"
VULNERABILITY_ID_MATCHED_KEY = "vulnerabilityIdMatched"


class OwaspDependencyCheckSummary(SummaryParser):

    @staticmethod
    def get_concerned_software(cve_report: Dict) -> "Optional[str]":
        """
        A CVE report always concern a vulnerability and is raised for one or more packages.
        In this report, there is a list of affected packages.
        Thus, for each package, the CVE report is able to inform if the vulnerability concerns the
        former with a key 'vulnerabilityIdMatched'.
        :param cve_report: The CVE report of a vulnerability from an OWASP dependency-check report
        :return: True if the current package is concerned
        """
        concerned_softwares = cve_report.get(VULNERABLE_SOFTWARE_KEY)
        for concerned_software in concerned_softwares:
            software = concerned_software.get(SOFTWARE_KEY)
            if VULNERABILITY_ID_MATCHED_KEY in software.keys():
                return software.get(ID_KEY)

        softwares = [soft.get(SOFTWARE_KEY) for soft in concerned_softwares]
        return str(" or ".join([soft.get(ID_KEY) for soft in softwares]))

    def parse(self, output: Optional[Path]) -> "None":
        """
        Each dependency is analyzed.
        For each dependency, it may appear 1 or more 'vulnerabilityIds' (packages ids).
        :return:
        """
        logger.debug(f"parsing report into a summary")
        reports: List[Report] = []
        c = 0
        for dependency in self.report.get(DEPENDENCIES_KEY):
            # only parse dependencies with vulnerabilities information
            c += 1
            if VULNERABILITIES_KEY in dependency.keys() and ".jar" in dependency.get(FILE_NAME_KEY):
                alerts = 0
                highest_severity = Severity.UNKNOWN
                vulnerabilities: List[Vulnerability] = []
                # assumption: one and only one package by vulnerability
                # package = dependency.get(PACKAGES_KEY)[0].get(ID_KEY)
                package = dependency.get(FILE_NAME_KEY)
                # each package has vulnerabilities concerning embedded components
                vulnerability_ids: List[str] = []
                if VULNERABILITY_IDS_KEY in dependency.keys():
                    vulnerability_ids = [section.get(ID_KEY) for section in
                                         dependency.get(VULNERABILITY_IDS_KEY)]
                else:
                    vulnerability_ids = ["NoF"]
                # for each component, check the CVE reports it is concerned about
                cves: Set[str] = set()
                for vulnerability_id in vulnerability_ids:
                    for vulnerability in dependency.get(VULNERABILITIES_KEY):
                        cve_name = vulnerability.get(NAME_KEY)
                        if cve_name not in cves:
                            cves.add(cve_name)
                            alerts += 1
                            cve_severity = Severity[str.upper(vulnerability.get(SEVERITY_KEY))]
                            self.update_count(cve_severity)
                            highest_severity = SummaryParser.get_highest_severity(highest_severity,
                                                                                  cve_severity)
                            concerned_software = OwaspDependencyCheckSummary\
                                .get_concerned_software(vulnerability)
                            vulnerabilities.append(Vulnerability(name=vulnerability.get(NAME_KEY),
                                                                 software=concerned_software,
                                                                 severity=cve_severity,
                                                                 description=vulnerability.get(
                                                                     DESCRIPTION_KEY)))

                self.reports.append(Report(source=package, alerts=alerts, highest=highest_severity,
                                           vulnerabilities=vulnerabilities))

        super().parse(output)
