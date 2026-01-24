#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Joomla Vulnerability Scanner
Detects Joomla installations for vulnerability scanning
"""

from kittysploit import *
from lib.protocols.http.http_client import Http_client


class Module(Scanner, Http_client):
    """Detects Joomla installations for vulnerability scanning"""

    __info__ = {
        'name': 'Joomla Vulnerability Scanner',
        'description': 'Detects Joomla installations for vulnerability scanning (versions, exposed files, misconfigurations)',
        'author': 'KittySploit Team',
        'tags': ['joomla', 'vulnerability', 'scanner', 'http'],
        'references': [
            'https://developer.joomla.org/security-centre.html'
        ],
        'module': 'auxiliary/scanner/http/joomla_scanner'
    }

    def run(self):
        """Check if Joomla is detected"""
        try:
            response = self.http_request(method="GET", path="/")
            if not response:
                return False
            
            # Detect Joomla using helper
            if self.if_joomla(response):
                self.set_info(reason='Joomla detected - run auxiliary scanner for detailed analysis')
                return True
            
            return False
        except:
            return False
