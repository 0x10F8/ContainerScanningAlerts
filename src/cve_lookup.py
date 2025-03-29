# -*- coding: utf-8 -*-
from cve import CVE
import requests

class CVELookup:

    API_URL = "https://cve.circl.lu/api/cve/"
    
    def lookup_cve_id(self, cve_id: str) -> CVE:
        """"
        Looks up a CVE ID and returns its details.
        """
        # API Call
        url = f"{self.API_URL}{cve_id}"
        # Simulating an API call for demonstration purposes
        # In a real scenario, you would use requests.get(url) and handle the response.
        # For this example, we will return a dummy CVE object.
        response = requests.get(url)
        if response.status_code == 200:
            data = response.json()
            cna = data.get('containers').get('cna')
            descriptions = cna.get('descriptions')
            description = ""
            for desc in descriptions:
                if desc.get('lang') == 'en':
                    description = desc.get('value')
                    break
            # Here we look for the cve details but if not found the cvss score is set to 0.0
            metrics = cna.get('metrics')
            if metrics and len(metrics) > 0:
                metrics = metrics[0]
            else:
                metrics = {}
            cvss_block = metrics.get('cvssV3_1', metrics.get('cvssV4_0', {}))
            cvss_score = cvss_block.get('baseScore', 0.0)
            return CVE(
                data['cveMetadata']['cveId'],  
                description, 
                cvss_score,
                data['cveMetadata']['datePublished'],
                data['cveMetadata']['dateUpdated']
                )
        else:
            raise Exception(f"Error fetching CVE data: {response.status_code}")