#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Nginx Vulnerability Scanner
Detects Nginx servers for vulnerability scanning
"""

from kittysploit import *
from lib.protocols.http.http_client import Http_client


class Module(Scanner, Http_client):
    """Detects Nginx servers for vulnerability scanning"""

    __info__ = {
        'name': 'Nginx Vulnerability Scanner',
        'description': 'Detects Nginx servers for vulnerability scanning (versions, misconfigurations, exposed files)',
        'author': 'KittySploit Team',
        'tags': ['nginx', 'vulnerability', 'scanner', 'http'],
        'references': [
            'https://nginx.org/en/security_advisories.html'
        ],
        'module': 'auxiliary/scanner/http/nginx_vuln_scanner'
    }

    def run(self):
        """Check if Nginx is detected"""
        try:
            response = self.http_request(method="GET", path="/")
            if not response:
                return False
            
            # Detect Nginx using helper
            version = self.if_nginx(response)
            if version:
                self.set_info(version=version, reason=f'Nginx {version} detected - run auxiliary scanner for detailed analysis')
                return True
            
            return False
        except:
            return False
