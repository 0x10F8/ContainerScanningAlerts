# -*- coding: utf-8 -*-
# This script scans a list of Docker images and versions for vulnerabilities using Grype.
# It parses the results and identifies vulnerabilities that are within or outwith a specified period.   
from grype_results_parser import GrypeResultsParser
from cyber_essentials_issue_finder import CyberEssentialsIssueFinder
from grype_scanner import GrypeScanner


images = [
    ("public.ecr.aws/lambda/python", "3.12.2025.03.28.05"), 
    ("public.ecr.aws/lambda/python", "3.9.2025.03.25.18"),
    ("public.ecr.aws/lambda/java", "17.2025.03.25.17"),
    ("public.ecr.aws/lambda/java", "11.2025.03.25.17"),
    ("debian", "12.10-slim"),
    ("alpine", "3.18.12"),

    ]

for image, version in images:
    print(f"Scanning image {image}:{version}...")
    scanner = GrypeScanner(image, version)
    grype_results = scanner.scan_image()
    parser = GrypeResultsParser(grype_results)
    parsed_results = parser.parse()
    within_period, outwith_period = CyberEssentialsIssueFinder.find_cyber_essentials_issues(parsed_results)
    print("Vulnerabilities within the period:")
    if len(within_period) == 0:
        print("None")
    for vulnerability in within_period:
        print(f"{vulnerability.vulnerability_id} {vulnerability.severity}")
    print("Vulnerabilities outwith the period:")
    if len(outwith_period) == 0:
        print("None")
    for vulnerability in outwith_period:
        print(f"{vulnerability.vulnerability_id} {vulnerability.severity}")
