#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Flask Debug Mode RCE Scanner
Detects Flask applications with debug mode enabled (Werkzeug console)
"""

from kittysploit import *
from lib.protocols.http.http_client import Http_client


class Module(Scanner, Http_client):
    """Detects Flask applications with debug mode enabled"""

    __info__ = {
        'name': 'Flask Debug Mode RCE Scanner',
        'description': 'Detects Flask applications with debug mode enabled, exposing Werkzeug console',
        'author': 'KittySploit Team',
        'tags': ['flask', 'werkzeug', 'debug', 'rce', 'scanner', 'http'],
        'references': [
            'https://werkzeug.palletsprojects.com/en/2.3.x/debug/'
        ],
        'module': 'exploits/http/flask_debug_rce'
    }

    def run(self):
        """Check if Flask debug mode is enabled"""
        try:
            # Check for Werkzeug console
            response = self.http_request(method="GET", path="/console", allow_redirects=False)
            if response and response.status_code == 200:
                content_lower = response.text.lower()
                if 'werkzeug' in content_lower and 'console' in content_lower:
                    self.set_info(reason='Flask debug console detected at /console')
                    return True
            
            # Check for debug error page
            response = self.http_request(method="GET", path="/nonexistent", allow_redirects=False)
            if response:
                content_lower = response.text.lower()
                if 'werkzeug' in content_lower and 'debug' in content_lower:
                    self.set_info(reason='Flask debug mode enabled (error page detected)')
                    return True
            
            return False
        except:
            return False
