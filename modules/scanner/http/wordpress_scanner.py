#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
WordPress Vulnerability Scanner
Detects WordPress installations for vulnerability scanning
"""

from kittysploit import *
from lib.protocols.http.http_client import Http_client


class Module(Scanner, Http_client):
    """Detects WordPress installations for vulnerability scanning"""

    __info__ = {
        'name': 'WordPress Vulnerability Scanner',
        'description': 'Detects WordPress installations for vulnerability scanning (versions, exposed files, misconfigurations)',
        'author': 'KittySploit Team',
        'tags': ['wordpress', 'wp', 'vulnerability', 'scanner', 'http'],
        'references': [
            'https://wordpress.org/support/article/faq-my-site-was-hacked/'
        ],
        'module': 'auxiliary/scanner/http/wordpress_scanner'
    }

    def run(self):
        """Check if WordPress is detected"""
        try:
            response = self.http_request(method="GET", path="/")
            if not response:
                return False
            
            # Detect WordPress using helper
            if self.if_wordpress(response):
                self.set_info(reason='WordPress detected - run auxiliary scanner for detailed analysis')
                return True
            
            return False
        except:
            return False
