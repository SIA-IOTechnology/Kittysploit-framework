#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Express.js RCE Scanner
Detects Express.js applications potentially vulnerable to RCE
"""

from kittysploit import *
from lib.protocols.http.http_client import Http_client


class Module(Scanner, Http_client):
    """Detects Express.js applications for potential RCE vulnerabilities"""

    __info__ = {
        'name': 'Express.js RCE Scanner',
        'description': 'Detects Express.js applications potentially vulnerable to RCE (template injection, code injection)',
        'author': 'KittySploit Team',
        'tags': ['express', 'expressjs', 'nodejs', 'rce', 'scanner', 'http'],
        'references': [
            'https://expressjs.com/en/advanced/security-updates.html'
        ],
        'module': 'exploits/http/express_rce'
    }

    def run(self):
        """Check if Express.js is detected"""
        try:
            response = self.http_request(method="GET", path="/")
            if not response:
                return False
            
            # Check for Express.js indicators
            powered_by = response.headers.get('X-Powered-By', '').lower()
            if 'express' in powered_by:
                self.set_info(reason='Express.js detected - potentially vulnerable to RCE')
                return True
            
            return False
        except:
            return False
