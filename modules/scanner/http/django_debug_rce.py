#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Django Debug Mode RCE Scanner
Detects Django applications with DEBUG=True enabled
"""

from kittysploit import *
from lib.protocols.http.http_client import Http_client


class Module(Scanner, Http_client):
    """Detects Django applications with debug mode enabled"""

    __info__ = {
        'name': 'Django Debug Mode RCE Scanner',
        'description': 'Detects Django applications with DEBUG=True enabled, exposing error pages and template injection',
        'author': 'KittySploit Team',
        'tags': ['django', 'debug', 'rce', 'template-injection', 'scanner', 'http'],
        'references': [
            'https://docs.djangoproject.com/en/stable/ref/settings/#debug'
        ],
        'module': 'exploits/http/django_debug_rce'
    }

    def run(self):
        """Check if Django debug mode is enabled"""
        try:
            # Trigger an error to check for debug page
            response = self.http_request(
                method="GET",
                path="/nonexistent-page-that-should-404/",
                allow_redirects=False
            )
            
            if response:
                content_lower = response.text.lower()
                # Check for Django debug page indicators
                if 'django' in content_lower and ('traceback' in content_lower or 'settings' in content_lower or 'debug' in content_lower):
                    self.set_info(reason='Django debug mode enabled - error page detected')
                    return True
            
            return False
        except:
            return False
