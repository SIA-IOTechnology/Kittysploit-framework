#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Python RCE Scanner
Detects Python applications potentially vulnerable to RCE
"""

from kittysploit import *
from lib.protocols.http.http_client import Http_client


class Module(Scanner, Http_client):
    """Detects Python applications for potential RCE vulnerabilities"""

    __info__ = {
        'name': 'Python RCE Scanner',
        'description': 'Detects Python applications potentially vulnerable to RCE (code injection, template injection, command injection)',
        'author': 'KittySploit Team',
        'tags': ['python', 'rce', 'code-injection', 'scanner', 'http'],
        'references': [
            'https://www.python.org/dev/security/'
        ],
        'module': 'exploits/http/python_rce'
    }

    def run(self):
        """Check if Python application is detected"""
        try:
            response = self.http_request(method="GET", path="/")
            if not response:
                return False
            
            # Check for Python indicators
            powered_by = response.headers.get('X-Powered-By', '').lower()
            server = response.headers.get('Server', '').lower()
            
            python_indicators = ['python', 'django', 'flask', 'werkzeug', 'gunicorn', 'uwsgi']
            if any(indicator in powered_by or indicator in server for indicator in python_indicators):
                self.set_info(reason='Python application detected - potentially vulnerable to RCE')
                return True
            
            return False
        except:
            return False
