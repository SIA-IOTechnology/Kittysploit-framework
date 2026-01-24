#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Debug Information Leak Scanner
Detects debug information leaks in HTTP responses
"""

from kittysploit import *
from lib.protocols.http.http_client import Http_client


class Module(Scanner, Http_client):
    """Detects debug information leaks"""

    __info__ = {
        'name': 'Debug Information Leak Scanner',
        'description': 'Detects debug information leaks (stack traces, error messages, version info, sensitive data)',
        'author': 'KittySploit Team',
        'tags': ['debug', 'information-disclosure', 'scanner', 'http'],
        'references': [
            'https://owasp.org/www-community/vulnerabilities/Information_exposure_through_debug_information'
        ],
        'module': 'auxiliary/scanner/http/debug_info_leak'
    }

    def run(self):
        """Check for debug information leaks"""
        try:
            # Check for debug endpoints
            debug_paths = ['/debug', '/test', '/dev', '/development', '/error', '/exception']
            
            for path in debug_paths:
                response = self.http_request(method="GET", path=path, allow_redirects=False)
                if response and response.status_code == 200:
                    content_lower = response.text.lower()
                    if any(indicator in content_lower for indicator in ['stack trace', 'traceback', 'exception', 'error', 'debug']):
                        self.set_info(reason=f'Debug information detected at {path} - run auxiliary scanner for detailed analysis')
                        return True
            
            return False
        except:
            return False
