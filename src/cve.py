# -*- coding: utf-8 -*-
from datetime import date

class CVE:
    """
    A class to represent a CVE (Common Vulnerabilities and Exposures) entry.
    """

    def __init__(self, cve_id: str, description: str, cvss_score: float, date_published: date, date_updated: date):
        """
        Initialize a CVE entry.

        :param cve_id: The CVE identifier (e.g., CVE-2023-12345).
        :param description: A brief description of the vulnerability.
        :param cvss_score: The CVSS score of the vulnerability.
        :param date_published: The date the CVE was published.
        :param date_updated: The date the CVE was last updated.
        """
        self.cve_id = cve_id
        self.description = description
        self.cvss_score = cvss_score
        self.date_published = date_published
        self.date_updated = date_updated

    def __repr__(self):
        return f"CVE({self.cve_id}, {self.description}, {self.cvss_score}, {self.date_updated})"