#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Java RCE Scanner
Detects Java applications potentially vulnerable to RCE
"""

from kittysploit import *
from lib.protocols.http.http_client import Http_client


class Module(Scanner, Http_client):
    """Detects Java applications for potential RCE vulnerabilities"""

    __info__ = {
        'name': 'Java RCE Scanner',
        'description': 'Detects Java applications potentially vulnerable to RCE (deserialization, Struts, Spring, etc.)',
        'author': 'KittySploit Team',
        'tags': ['java', 'rce', 'deserialization', 'struts', 'spring', 'scanner', 'http'],
        'references': [
            'https://www.oracle.com/security-alerts/'
        ],
        'module': 'exploits/http/java_rce'
    }

    def run(self):
        """Check if Java application is detected"""
        try:
            response = self.http_request(method="GET", path="/")
            if not response:
                return False
            
            # Check for Java indicators
            server = response.headers.get('Server', '').lower()
            powered_by = response.headers.get('X-Powered-By', '').lower()
            
            java_indicators = ['tomcat', 'jboss', 'weblogic', 'websphere', 'jetty', 'glassfish']
            if any(indicator in server or indicator in powered_by for indicator in java_indicators):
                self.set_info(reason='Java application detected - potentially vulnerable to RCE (deserialization, Struts, etc.)')
                return True
            
            return False
        except:
            return False
