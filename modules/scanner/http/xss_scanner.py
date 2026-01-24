#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
XSS Scanner
Detects potential Cross-Site Scripting vulnerabilities
"""

from kittysploit import *
from lib.protocols.http.http_client import Http_client


class Module(Scanner, Http_client):
    """Detects potential XSS vulnerabilities"""

    __info__ = {
        'name': 'XSS Scanner',
        'description': 'Detects potential Cross-Site Scripting vulnerabilities (reflected, stored, DOM-based)',
        'author': 'KittySploit Team',
        'tags': ['xss', 'cross-site-scripting', 'scanner', 'http'],
        'references': [
            'https://owasp.org/www-community/attacks/xss/'
        ],
        'module': 'auxiliary/scanner/http/xss_scanner'
    }

    def run(self):
        """Check for potential XSS"""
        try:
            # Basic check: look for forms or parameters that might be vulnerable
            response = self.http_request(method="GET", path="/")
            if not response:
                return False
            
            # Check for common XSS indicators in forms
            content_lower = response.text.lower()
            if any(indicator in content_lower for indicator in ['<form', '<input', '?q=', '?search=', '?name=', '?comment=']):
                self.set_info(reason='Forms or parameters detected - run auxiliary scanner for XSS testing')
                return True
            
            return False
        except:
            return False
