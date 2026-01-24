#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
SSRF Scanner
Detects potential Server-Side Request Forgery vulnerabilities
"""

from kittysploit import *
from lib.protocols.http.http_client import Http_client


class Module(Scanner, Http_client):
    """Detects potential SSRF vulnerabilities"""

    __info__ = {
        'name': 'SSRF Scanner',
        'description': 'Detects potential Server-Side Request Forgery vulnerabilities (internal network access, cloud metadata, protocol handlers)',
        'author': 'KittySploit Team',
        'tags': ['ssrf', 'server-side-request-forgery', 'scanner', 'http'],
        'references': [
            'https://owasp.org/www-community/attacks/Server_Side_Request_Forgery'
        ],
        'module': 'auxiliary/scanner/http/ssrf_scanner'
    }

    def run(self):
        """Check for potential SSRF"""
        try:
            # Basic check: look for URL parameters that might be vulnerable
            response = self.http_request(method="GET", path="/")
            if not response:
                return False
            
            # Check for common SSRF indicators
            content_lower = response.text.lower()
            if any(indicator in content_lower for indicator in ['?url=', '?link=', '?target=', '?redirect=', '?fetch=', '?proxy=']):
                self.set_info(reason='URL parameters detected - run auxiliary scanner for SSRF testing')
                return True
            
            return False
        except:
            return False
