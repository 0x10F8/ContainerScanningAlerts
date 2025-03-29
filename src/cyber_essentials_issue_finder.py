# -*- coding: utf-8 -*-
from vulnerability import ContainerVulnerability
from severity import Severity
from datetime import datetime, timedelta

class CyberEssentialsIssueFinder:

    HIGH = 7.0
    TODAY = datetime.today()
    FOURTEEN_DAYS_AGO = TODAY - timedelta(days=14)

    def find_cyber_essentials_issues(data: list[ContainerVulnerability]) -> tuple[list[ContainerVulnerability], list[ContainerVulnerability]]:
        """
        Find high and critical issues in the provided data.
        
        :param data: A list of ContainerVulnerability objects.
        :return: A tuple containing two lists: one for vulnerabilities within the period and one for those outwith the period.
        """
        within_period = []
        outwith_period = []
        for vulnerability in data:
            if vulnerability.severity == Severity.HIGH or vulnerability.severity == Severity.CRITICAL:
                contains_high_cve_outwith_period = False
                for cve_details in vulnerability.associated_cves:
                    if cve_details.cvss_score >= CyberEssentialsIssueFinder.HIGH:
                        cve_date_updated = datetime.strptime(cve_details.date_updated, '%Y-%m-%dT%H:%M:%S.%fZ')
                        if cve_date_updated < CyberEssentialsIssueFinder.FOURTEEN_DAYS_AGO:
                            contains_high_cve_outwith_period = True
                            break
                if contains_high_cve_outwith_period:
                    outwith_period.append(vulnerability)
                else:
                    within_period.append(vulnerability)
        return within_period, outwith_period