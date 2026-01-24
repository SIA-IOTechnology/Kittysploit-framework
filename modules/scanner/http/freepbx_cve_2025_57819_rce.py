#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
FreePBX CVE-2025-57819 RCE Scanner
Detects FreePBX vulnerable to unauthenticated SQL injection to RCE
"""

from kittysploit import *
from lib.protocols.http.http_client import Http_client


class Module(Scanner, Http_client):
    """Detects FreePBX vulnerable to CVE-2025-57819"""

    __info__ = {
        'name': 'FreePBX CVE-2025-57819 RCE Scanner',
        'description': 'Detects FreePBX vulnerable to unauthenticated SQL injection to RCE (CVE-2025-57819)',
        'author': 'KittySploit Team',
        'tags': ['freepbx', 'cve-2025-57819', 'sqli', 'rce', 'scanner', 'http'],
        'references': [
            'CVE-2025-57819',
            'https://nvd.nist.gov/vuln/detail/CVE-2025-57819'
        ],
        'module': 'exploits/unix/webapp/http/freepbx_cve_2025_57819_rce'
    }

    def run(self):
        """Check if FreePBX is vulnerable"""
        try:
            # Check for FreePBX installation
            response = self.http_request(method="GET", path="/admin/config.php", allow_redirects=False)
            if response and response.status_code == 200:
                # Check for FreePBX indicators
                content_lower = response.text.lower()
                if 'freepbx' in content_lower or 'asterisk' in content_lower:
                    # Check for ajax.php endpoint (vulnerable endpoint)
                    ajax_response = self.http_request(method="GET", path="/admin/modules/framework/ajax.php", allow_redirects=False)
                    if ajax_response:
                        self.set_info(reason='FreePBX detected with ajax.php endpoint - potentially vulnerable to CVE-2025-57819')
                        return True
            
            return False
        except:
            return False
