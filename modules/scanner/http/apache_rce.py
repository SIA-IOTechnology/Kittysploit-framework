#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Apache HTTP Server RCE Scanner
Detects Apache servers potentially vulnerable to RCE via mod_cgi, mod_rewrite, etc.
"""

from kittysploit import *
from lib.protocols.http.http_client import Http_client


class Module(Scanner, Http_client):
    """Detects Apache HTTP Server for potential RCE vulnerabilities"""

    __info__ = {
        'name': 'Apache HTTP Server RCE Scanner',
        'description': 'Detects Apache HTTP Server for potential RCE vulnerabilities (mod_cgi, mod_rewrite, etc.)',
        'author': 'KittySploit Team',
        'tags': ['apache', 'rce', 'mod_cgi', 'scanner', 'http'],
        'references': [
            'https://httpd.apache.org/security/'
        ],
        'module': 'exploits/http/apache_rce'
    }

    def run(self):
        """Check if Apache server is detected"""
        try:
            response = self.http_request(method="GET", path="/")
            if not response:
                return False
            
            # Detect Apache using helper
            version = self.if_apache(response)
            if version:
                self.set_info(version=version, reason=f'Apache {version} detected - potential RCE via mod_cgi/mod_rewrite')
                return True
            
            return False
        except:
            return False
