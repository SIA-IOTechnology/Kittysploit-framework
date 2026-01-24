#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Apache Vulnerability Scanner
Detects Apache servers for vulnerability scanning
"""

from kittysploit import *
from lib.protocols.http.http_client import Http_client


class Module(Scanner, Http_client):
    """Detects Apache servers for vulnerability scanning"""

    __info__ = {
        'name': 'Apache Vulnerability Scanner',
        'description': 'Detects Apache servers for vulnerability scanning (versions, misconfigurations, exposed files)',
        'author': 'KittySploit Team',
        'tags': ['apache', 'vulnerability', 'scanner', 'http'],
        'references': [
            'https://httpd.apache.org/security/'
        ],
        'module': 'auxiliary/scanner/http/apache_vuln_scanner'
    }

    def run(self):
        """Check if Apache is detected"""
        try:
            response = self.http_request(method="GET", path="/")
            if not response:
                return False
            
            # Detect Apache using helper
            version = self.if_apache(response)
            if version:
                self.set_info(version=version, reason=f'Apache {version} detected - run auxiliary scanner for detailed analysis')
                return True
            
            return False
        except:
            return False
