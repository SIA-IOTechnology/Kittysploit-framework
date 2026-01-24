#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Flowise JS Injection RCE Scanner
Detects Flowise vulnerable to CVE-2025-59528 (JavaScript code injection)
"""

from kittysploit import *
from lib.protocols.http.http_client import Http_client


class Module(Scanner, Http_client):
    """Detects Flowise vulnerable to CVE-2025-59528"""

    __info__ = {
        'name': 'Flowise JS Injection RCE Scanner',
        'description': 'Detects Flowise vulnerable to JavaScript code injection in customMCP endpoint (CVE-2025-59528)',
        'author': 'KittySploit Team',
        'tags': ['flowise', 'cve-2025-59528', 'js-injection', 'rce', 'scanner', 'http'],
        'references': [
            'CVE-2025-59528',
            'EDB-52440'
        ],
        'module': 'exploits/multi/http/flowise_js_injection_rce'
    }

    def run(self):
        """Check if Flowise is vulnerable"""
        try:
            # Check for Flowise installation
            response = self.http_request(method="GET", path="/", allow_redirects=False)
            if response:
                # Check for Flowise indicators
                content_lower = response.text.lower()
                headers_lower = {k.lower(): v.lower() for k, v in response.headers.items()}
                
                if 'flowise' in content_lower or 'flowise' in str(headers_lower):
                    # Check for vulnerable customMCP endpoint
                    api_response = self.http_request(method="GET", path="/api/v1/customMCP", allow_redirects=False)
                    if api_response:
                        self.set_info(reason='Flowise detected with customMCP endpoint - potentially vulnerable to CVE-2025-59528')
                        return True
            
            return False
        except:
            return False
