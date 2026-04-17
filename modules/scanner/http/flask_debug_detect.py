#!/usr/bin/env python3
# -*- coding: utf-8 -*-

from kittysploit import *
from lib.protocols.http.http_client import Http_client

class Module(Scanner, Http_client):

    __info__ = {
        'name': 'Flask Debug Mode detection',
        'description': 'Detects if Flask debug mode (Werkzeug) is enabled on the target, which may lead to RCE.',
        'author': 'KittySploit Team',
        'severity': 'high',
        'modules': ['exploits/http/flask_debug_rce'],
        'tags': ['web', 'scanner', 'flask', 'werkzeug', 'debug', 'rce'],
    }

    def run(self):
        try:
            # Check for Werkzeug console
            response = self.http_request(method="GET", path="/console", allow_redirects=False)
            if response and response.status_code == 200:
                if 'werkzeug' in response.text.lower() or 'console' in response.text.lower():
                    self.set_info(severity="high", reason="Flask Werkzeug debug console detected")
                    return True
            
            # Check for debug error page
            response = self.http_request(method="GET", path="/nonexistent-page-for-flask-check", allow_redirects=False)
            if response:
                content = response.text.lower()
                if 'werkzeug' in content and 'debug' in content:
                    self.set_info(severity="high", reason="Flask Werkzeug debug mode enabled")
                    return True
            
            return False
        except Exception:
            return False
