#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
WordPress RCE Scanner
Detects WordPress installations potentially vulnerable to RCE
"""

from kittysploit import *
from lib.protocols.http.http_client import Http_client


class Module(Scanner, Http_client):
    """Detects WordPress installations for potential RCE vulnerabilities"""

    __info__ = {
        'name': 'WordPress RCE Scanner',
        'description': 'Detects WordPress installations potentially vulnerable to RCE (plugins, core vulnerabilities)',
        'author': 'KittySploit Team',
        'tags': ['wordpress', 'wp', 'rce', 'cms', 'scanner', 'http'],
        'references': [
            'https://wordpress.org/security/'
        ],
        'module': 'exploits/http/wordpress_rce'
    }

    def run(self):
        """Check if WordPress is detected"""
        try:
            response = self.http_request(method="GET", path="/")
            if not response:
                return False
            
            # Detect WordPress using helper
            if self.if_wordpress(response):
                self.set_info(reason='WordPress detected - potentially vulnerable to RCE via plugins or core vulnerabilities')
                return True
            
            return False
        except:
            return False
