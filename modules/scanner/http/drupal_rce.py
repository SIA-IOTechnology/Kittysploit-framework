#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Drupal RCE Scanner
Detects Drupal installations potentially vulnerable to RCE (Drupalgeddon, etc.)
"""

from kittysploit import *
from lib.protocols.http.http_client import Http_client


class Module(Scanner, Http_client):
    """Detects Drupal installations for potential RCE vulnerabilities"""

    __info__ = {
        'name': 'Drupal RCE Scanner',
        'description': 'Detects Drupal installations potentially vulnerable to RCE (Drupalgeddon CVE-2018-7600, CVE-2018-7602, etc.)',
        'author': 'KittySploit Team',
        'tags': ['drupal', 'rce', 'drupalgeddon', 'cve-2018-7600', 'cms', 'scanner', 'http'],
        'references': [
            'CVE-2018-7600',
            'CVE-2018-7602',
            'https://www.drupal.org/security'
        ],
        'module': 'exploits/http/drupal_rce'
    }

    def run(self):
        """Check if Drupal is detected"""
        try:
            response = self.http_request(method="GET", path="/")
            if not response:
                return False
            
            # Detect Drupal using helper
            if self.if_drupal(response):
                self.set_info(reason='Drupal detected - potentially vulnerable to RCE (Drupalgeddon)')
                return True
            
            return False
        except:
            return False
