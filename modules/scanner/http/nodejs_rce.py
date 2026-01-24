#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Node.js RCE Scanner
Detects Node.js applications potentially vulnerable to RCE
"""

from kittysploit import *
from lib.protocols.http.http_client import Http_client


class Module(Scanner, Http_client):
    """Detects Node.js applications for potential RCE vulnerabilities"""

    __info__ = {
        'name': 'Node.js RCE Scanner',
        'description': 'Detects Node.js applications potentially vulnerable to RCE (template injection, code injection, command injection)',
        'author': 'KittySploit Team',
        'tags': ['nodejs', 'node', 'rce', 'code-injection', 'scanner', 'http'],
        'references': [
            'https://nodejs.org/en/security/'
        ],
        'module': 'exploits/http/nodejs_rce'
    }

    def run(self):
        """Check if Node.js is detected"""
        try:
            response = self.http_request(method="GET", path="/")
            if not response:
                return False
            
            # Check for Node.js indicators
            powered_by = response.headers.get('X-Powered-By', '').lower()
            if 'node' in powered_by or 'express' in powered_by:
                self.set_info(reason='Node.js detected - potentially vulnerable to RCE')
                return True
            
            return False
        except:
            return False
