#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Drupal Vulnerability Scanner
Detects Drupal installations for vulnerability scanning
"""

from kittysploit import *
from lib.protocols.http.http_client import Http_client


class Module(Scanner, Http_client):
    """Detects Drupal installations for vulnerability scanning"""

    __info__ = {
        'name': 'Drupal Vulnerability Scanner',
        'description': 'Detects Drupal installations for vulnerability scanning (versions, exposed files, misconfigurations)',
        'author': 'KittySploit Team',
        'tags': ['drupal', 'vulnerability', 'scanner', 'http'],
        'references': [
            'https://www.drupal.org/security'
        ],
        'module': 'auxiliary/scanner/http/drupal_scanner'
    }

    def run(self):
        """Check if Drupal is detected"""
        try:
            response = self.http_request(method="GET", path="/")
            if not response:
                return False
            
            # Detect Drupal using helper
            if self.if_drupal(response):
                self.set_info(reason='Drupal detected - run auxiliary scanner for detailed analysis')
                return True
            
            return False
        except:
            return False
