#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Debug Mode RCE Scanner
Detects applications with debug/development mode enabled
"""

from kittysploit import *
from lib.protocols.http.http_client import Http_client


class Module(Scanner, Http_client):
    """Detects applications with debug mode enabled (Django, Flask, etc.)"""

    __info__ = {
        'name': 'Debug Mode RCE Scanner',
        'description': 'Detects applications with debug/development mode enabled (Django, Flask, etc.)',
        'author': 'KittySploit Team',
        'tags': ['debug', 'development', 'rce', 'scanner', 'http'],
        'references': [
            'https://docs.djangoproject.com/en/stable/ref/settings/#debug',
            'https://werkzeug.palletsprojects.com/en/2.3.x/debug/'
        ],
        'module': 'exploits/http/debug_rce'
    }

    def run(self):
        """Check if debug mode is enabled"""
        try:
            # Check for common debug endpoints
            debug_paths = ['/console', '/debug', '/_debug', '/dev', '/development']
            
            for path in debug_paths:
                response = self.http_request(method="GET", path=path, allow_redirects=False)
                if response and response.status_code == 200:
                    content_lower = response.text.lower()
                    if 'debug' in content_lower or 'console' in content_lower or 'werkzeug' in content_lower:
                        self.set_info(reason=f'Debug endpoint found at {path} - potentially vulnerable to RCE')
                        return True
            
            return False
        except:
            return False
