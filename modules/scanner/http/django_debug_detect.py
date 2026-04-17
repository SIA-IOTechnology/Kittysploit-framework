#!/usr/bin/env python3
# -*- coding: utf-8 -*-

from kittysploit import *
from lib.protocols.http.http_client import Http_client

class Module(Scanner, Http_client):

    __info__ = {
        'name': 'Django Debug Mode detection',
        'description': 'Detects if Django debug mode is enabled on the target, which may lead to information disclosure or RCE.',
        'author': 'KittySploit Team',
        'severity': 'high',
        'modules': ['exploits/http/django_debug_rce'],
        'tags': ['web', 'scanner', 'django', 'debug', 'rce'],
    }

    def run(self):
        try:
            # Trigger an error to check for debug page
            response = self.http_request(
                method="GET",
                path="/nonexistent-page-that-should-404-for-django-debug-check/",
                allow_redirects=False
            )
            
            if response:
                content = response.text.lower()
                # Check for Django debug page indicators
                if 'django' in content and ('traceback' in content or 'settings' in content or 'debug' in content):
                    self.set_info(severity="high", reason="Django debug mode is enabled")
                    return True
            
            return False
        except Exception:
            return False
