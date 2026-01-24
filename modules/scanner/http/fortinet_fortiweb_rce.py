#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Fortinet FortiWeb RCE Scanner
Detects FortiWeb vulnerable to CVE-2025-64446 (auth bypass) and CVE-2025-58034 (RCE)
"""

from kittysploit import *
from lib.protocols.http.http_client import Http_client


class Module(Scanner, Http_client):
    """Detects FortiWeb vulnerable to CVE-2025-64446 and CVE-2025-58034"""

    __info__ = {
        'name': 'Fortinet FortiWeb RCE Scanner',
        'description': 'Detects FortiWeb vulnerable to auth bypass (CVE-2025-64446) and RCE (CVE-2025-58034)',
        'author': 'KittySploit Team',
        'tags': ['fortinet', 'fortiweb', 'cve-2025-64446', 'cve-2025-58034', 'rce', 'scanner', 'http'],
        'references': [
            'CVE-2025-64446',
            'CVE-2025-58034',
            'https://www.fortiguard.com/psirt/FG-IR-25-910',
            'https://www.fortiguard.com/psirt/FG-IR-25-513'
        ],
        'module': 'exploits/linux/http/fortinet_fortiweb_rce'
    }

    def run(self):
        """Check if FortiWeb is vulnerable"""
        try:
            # Check for FortiWeb login page
            response = self.http_request(method="GET", path="/", allow_redirects=False)
            if response:
                # Check for FortiWeb indicators
                content_lower = response.text.lower()
                headers_lower = {k.lower(): v.lower() for k, v in response.headers.items()}
                
                if 'fortiweb' in content_lower or 'fortiweb' in str(headers_lower):
                    # Check for vulnerable endpoints
                    api_response = self.http_request(method="GET", path="/api/v2.0/system/admin_user", allow_redirects=False)
                    if api_response:
                        self.set_info(reason='FortiWeb detected - potentially vulnerable to CVE-2025-64446 and CVE-2025-58034')
                        return True
            
            return False
        except:
            return False
