#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
n8n Full Chain RCE Scanner
Detects n8n vulnerable to CVE-2026-21858 (LFI) and CVE-2025-68613 (RCE)
"""

from kittysploit import *
from lib.protocols.http.http_client import Http_client


class Module(Scanner, Http_client):
    """Detects n8n vulnerable to CVE-2026-21858 and CVE-2025-68613"""

    __info__ = {
        'name': 'n8n Full Chain RCE Scanner',
        'description': 'Detects n8n vulnerable to LFI (CVE-2026-21858) and RCE (CVE-2025-68613)',
        'author': 'KittySploit Team',
        'tags': ['n8n', 'cve-2026-21858', 'cve-2025-68613', 'lfi', 'rce', 'scanner', 'http'],
        'references': [
            'CVE-2026-21858',
            'CVE-2025-68613',
            'https://github.com/Chocapikk/CVE-2026-21858'
        ],
        'module': 'exploits/linux/http/n8n_full_chain_rce'
    }

    def run(self):
        """Check if n8n is vulnerable"""
        try:
            # Check for n8n installation
            response = self.http_request(method="GET", path="/", allow_redirects=False)
            if response:
                # Check for n8n indicators
                content_lower = response.text.lower()
                headers_lower = {k.lower(): v.lower() for k, v in response.headers.items()}
                
                if 'n8n' in content_lower or 'n8n' in str(headers_lower):
                    # Check for vulnerable form upload endpoint
                    form_response = self.http_request(method="GET", path="/form/upload", allow_redirects=False)
                    if form_response:
                        self.set_info(reason='n8n detected with form upload endpoint - potentially vulnerable to CVE-2026-21858 and CVE-2025-68613')
                        return True
            
            return False
        except:
            return False
