# -*- coding: utf-8 -*-
from enum import Enum

class Severity(Enum):
    """
    An enumeration to represent the severity levels of vulnerabilities.
    """
    UNKNOWN = "Unknown"
    LOW = "Low"
    MEDIUM = "Medium"
    HIGH = "High"
    CRITICAL = "Critical"

    def __str__(self):
        return self.value

    def from_string(severity_str: str) ->'Severity':
        """
        Converts a string to a Severity enum.

        :param severity_str: str: The severity string.
        :return: Severity: The corresponding Severity enum.
        """
        severity_map = {
            "unknown": Severity.UNKNOWN,
            "low": Severity.LOW,
            "medium": Severity.MEDIUM,
            "high": Severity.HIGH,
            "critical": Severity.CRITICAL,
        }
        return severity_map.get(severity_str.lower().strip(), Severity.UNKNOWN)
    