#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
LFI Fuzzer Scanner
Detects potential Local File Inclusion vulnerabilities
"""

from kittysploit import *
from lib.protocols.http.http_client import Http_client


class Module(Scanner, Http_client):
    """Detects potential LFI vulnerabilities"""

    __info__ = {
        'name': 'LFI Fuzzer Scanner',
        'description': 'Detects potential Local File Inclusion vulnerabilities (path traversal, file inclusion)',
        'author': 'KittySploit Team',
        'tags': ['lfi', 'local-file-inclusion', 'path-traversal', 'scanner', 'http'],
        'references': [
            'https://owasp.org/www-community/vulnerabilities/Path_Traversal'
        ],
        'module': 'auxiliary/scanner/http/lfi_fuzzer'
    }

    def run(self):
        """Check for potential LFI"""
        try:
            # Basic check: look for file parameters
            response = self.http_request(method="GET", path="/")
            if not response:
                return False
            
            # Check for common LFI indicators
            content_lower = response.text.lower()
            if any(indicator in content_lower for indicator in ['?file=', '?page=', '?include=', '?path=', '?doc=']):
                self.set_info(reason='File parameters detected - run auxiliary scanner for LFI testing')
                return True
            
            return False
        except:
            return False
