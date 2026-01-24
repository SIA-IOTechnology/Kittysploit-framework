#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
PHP RCE Scanner
Detects PHP applications potentially vulnerable to RCE
"""

from kittysploit import *
from lib.protocols.http.http_client import Http_client


class Module(Scanner, Http_client):
    """Detects PHP applications for potential RCE vulnerabilities"""

    __info__ = {
        'name': 'PHP RCE Scanner',
        'description': 'Detects PHP applications potentially vulnerable to RCE (code injection, file upload, etc.)',
        'author': 'KittySploit Team',
        'tags': ['php', 'rce', 'code-injection', 'scanner', 'http'],
        'references': [
            'https://www.php.net/security/'
        ],
        'module': 'exploits/http/php_rce'
    }

    def run(self):
        """Check if PHP is detected"""
        try:
            response = self.http_request(method="GET", path="/")
            if not response:
                return False
            
            # Detect PHP using helper
            version = self.if_php(response)
            if version:
                self.set_info(version=version, reason=f'PHP {version} detected - potentially vulnerable to RCE')
                return True
            
            return False
        except:
            return False
