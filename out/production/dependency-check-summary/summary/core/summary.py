from typing import Dict, List, Optional

from summary.lib.utils import logger_utils
from summary.models.summary_model import Overview, Severity, Summary, Vulnerability

logger = logger_utils.get_logger(__name__)

ID_KEY = "id"
DEPENDENCIES_KEY = "dependencies"
DESCRIPTION_KEY = "description"
NAME_KEY = "name"
PACKAGES_KEY = "packages"
SEVERITY_KEY = "severity"
SOFTWARE_KEY = "software"
VULNERABILITY_IDS_KEY = "vulnerabilityIds"
VULNERABILITIES_KEY = "vulnerabilities"
VULNERABLE_SOFTWARE_KEY = "vulnerableSoftware"
VULNERABILITY_ID_MATCHED_KEY = "vulnerabilityIdMatched"


class SummaryParser(object):
    summary: Summary
    ids: List[str] = []
    critical_count = 0
    high_count = 0
    medium_count = 0
    low_count = 0

    def __init__(self, report: Dict):
        """
        :param report: Content of the JSON report
        """
        self.report = report

    def update_count(self, severity: str):
        if Severity.LOW == severity:
            self.low_count += 1
        elif Severity.MEDIUM == severity:
            self.medium_count += 1
        elif Severity.HIGH == severity:
            self.high_count += 1
        elif Severity.CRITICAL == severity:
            self.critical_count += 1
        else:
            logger.warn(f"Skip unknown severity '{severity}'")

    def get_vulnerabilities(self, dependency: Dict) -> "Dict[str, Vulnerability]":
        """
        For each 'vulnerabilityId' (package id), it may appear 1 or more 'vulnerabilities' (CVE).
        We have to iterate over the package id and for each :
          - concatenate the current 'vulnerabilityId' with the CVE name to produce a new id
          - store this new id in a list to remember we already take it into account
        :param dependency: dependency section containing a 'vulnerabilityIds' section and a
                           'vulnerabilities' section, for which we have to count one vulnerability
                           per 'vulnerabilityId'
        :return:
        """
        vulnerabilities: Dict[str, Vulnerability] = {}
        # get all the vulnerability package ids
        package_ids = [pack_id.get("id") for pack_id in dependency.get(VULNERABILITY_IDS_KEY)]
        # for each id, get all the vulnerabilities sections that concerns the package
        for pack_id in package_ids:
            if pack_id not in self.ids:
                self.ids.append(vulnerability_uuid)

            for vulnerability in dependency.get(VULNERABILITIES_KEY):
                vulnerability_name = vulnerability.get("name")
                # build a new vulnerability id unique per package
                vulnerability_uuid = pack_id + "-" + vulnerability_name
                # if the new vulnerability uuid is not already considered by the current parser
                # we add it and parse it
                if vulnerability_uuid not in self.ids:
                    self.ids.append(vulnerability_uuid)
                    # severity count
                    self.update_count(vulnerability.get('severity'))
                    # vulnerability parsing
                    v = Vulnerability.parse_obj(vulnerability)
                    # vulnerabilities.update(pack_id, v)

        return vulnerabilities

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

        return None

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

    def parse(self) -> "Summary":
        """
        Each dependency is analyzed.
        For each dependency, it may appear 1 or more 'vulnerabilityIds' (packages ids).
        :return:
        """
        logger.debug(f"parsing report into a summary")
        for dependency in self.report.get(DEPENDENCIES_KEY):
            # only parse dependencies with vulnerabilities information
            if VULNERABILITIES_KEY in dependency.keys():
                highest_severity = Severity.LOW
                vulnerabilities: List[Vulnerability] = []
                # assumption: one and only one package by vulnerability
                package = dependency.get(PACKAGES_KEY)[0].get(ID_KEY)
                # each package has vulnerabilities concerning embedded components
                vulnerability_ids: List[str] = [section.get(ID_KEY) for section in
                                                dependency.get(VULNERABILITY_IDS_KEY)]
                # for each component, check the CVE reports it is concerned about
                for vulnerability_id in vulnerability_ids:
                    for cve_report in dependency.get(VULNERABILITIES_KEY):
                        # check what CVE concerns this vulnerability
                        concerned_software = SummaryParser.get_concerned_software(cve_report)
                        vulnerabilities.append(Vulnerability(name=cve_report.get(NAME_KEY), software=concerned_software, severity=cve_report.get(SEVERITY_KEY), description=cve_report.get(DESCRIPTION_KEY)))
                        logger.info("issou")

        overview = Overview(critical=self.critical_count,
                            high=self.high_count,
                            medium=self.medium_count,
                            low=self.low_count)

        raise NotImplementedError
