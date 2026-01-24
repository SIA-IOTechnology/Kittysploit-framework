#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Joomla RCE Scanner
Detects Joomla installations potentially vulnerable to RCE
"""

from kittysploit import *
from lib.protocols.http.http_client import Http_client


class Module(Scanner, Http_client):
    """Detects Joomla installations for potential RCE vulnerabilities"""

    __info__ = {
        'name': 'Joomla RCE Scanner',
        'description': 'Detects Joomla installations potentially vulnerable to RCE (template injection, file upload, etc.)',
        'author': 'KittySploit Team',
        'tags': ['joomla', 'rce', 'cms', 'scanner', 'http'],
        'references': [
            'https://developer.joomla.org/security-centre.html'
        ],
        'module': 'exploits/http/joomla_rce'
    }

    def run(self):
        """Check if Joomla is detected"""
        try:
            response = self.http_request(method="GET", path="/")
            if not response:
                return False
            
            # Detect Joomla using helper
            if self.if_joomla(response):
                self.set_info(reason='Joomla detected - potentially vulnerable to RCE via template injection or file upload')
                return True
            
            return False
        except:
            return False
