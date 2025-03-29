# -*- coding: utf-8 -*-
from vulnerability import ContainerVulnerability
from severity import Severity
from state import State
from cve_lookup import CVELookup
from vulnerability import ContainerVulnerability

class GrypeResultsParser:
    """
    A class to parse Grype results and extract relevant information.
    """

    def __init__(self, grype_results: dict):
        """
        Initializes the GrypeResultsParser with the provided Grype results.

        :param grype_results: dict: The Grype results in JSON format.
        """
        self.grype_results = grype_results

    def parse(self) -> list[ContainerVulnerability]:
        """
        Parses the Grype results and extracts relevant information.

        :return: A list of ContainerVulnerability objects with the parsed information.
        """
        parsed_results = []

        matches = self.grype_results['matches']
        for match in matches:
            vulnerability_id = match['vulnerability']['id']
            severity = Severity.from_string(match['vulnerability']['severity'])
            state = State.from_string(match.get('vulnerability', {}).get('fix', {}).get('state', 'unknown'))
            url = match['vulnerability'].get('dataSource')
            description = match['vulnerability'].get('description', '')
            cve_ids = [epss['cve'] for epss in match['vulnerability'].get('epss', [])]
            associated_cves = []
            lookup = CVELookup()
            for cve_id in cve_ids:
                cve = lookup.lookup_cve_id(cve_id)
                associated_cves.append(cve)
            parsed_results.append(ContainerVulnerability(vulnerability_id, severity, url, description, associated_cves, state))

        return parsed_results