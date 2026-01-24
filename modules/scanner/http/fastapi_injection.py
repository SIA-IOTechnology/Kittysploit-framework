#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
FastAPI Injection RCE Scanner
Detects FastAPI applications potentially vulnerable to RCE
"""

from kittysploit import *
from lib.protocols.http.http_client import Http_client


class Module(Scanner, Http_client):
    """Detects FastAPI applications for potential RCE vulnerabilities"""

    __info__ = {
        'name': 'FastAPI Injection RCE Scanner',
        'description': 'Detects FastAPI applications potentially vulnerable to RCE (template injection, code injection)',
        'author': 'KittySploit Team',
        'tags': ['fastapi', 'python', 'rce', 'injection', 'scanner', 'http'],
        'references': [
            'https://fastapi.tiangolo.com/'
        ],
        'module': 'exploits/http/fastapi_injection'
    }

    def run(self):
        """Check if FastAPI is detected"""
        try:
            # Check for FastAPI Swagger docs
            response = self.http_request(method="GET", path="/docs", allow_redirects=False)
            if response and response.status_code == 200:
                content_lower = response.text.lower()
                if 'swagger' in content_lower or 'fastapi' in content_lower:
                    self.set_info(reason='FastAPI detected (Swagger docs found) - potentially vulnerable to RCE')
                    return True
            
            return False
        except:
            return False
