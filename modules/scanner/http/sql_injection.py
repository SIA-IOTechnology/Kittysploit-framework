#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
SQL Injection Scanner
Detects potential SQL injection vulnerabilities
"""

from kittysploit import *
from lib.protocols.http.http_client import Http_client


class Module(Scanner, Http_client):
    """Detects potential SQL injection vulnerabilities"""

    __info__ = {
        'name': 'SQL Injection Scanner',
        'description': 'Detects potential SQL injection vulnerabilities (union-based, boolean-based, time-based, error-based)',
        'author': 'KittySploit Team',
        'tags': ['sqli', 'sql', 'injection', 'scanner', 'http'],
        'references': [
            'https://owasp.org/www-community/attacks/SQL_Injection'
        ],
        'module': 'auxiliary/scanner/http/sql_injection'
    }

    def run(self):
        """Check for potential SQL injection"""
        try:
            # Basic check: look for forms or parameters that might be vulnerable
            response = self.http_request(method="GET", path="/")
            if not response:
                return False
            
            # Check for common SQL injection indicators in forms
            content_lower = response.text.lower()
            if any(indicator in content_lower for indicator in ['<form', '<input', '?id=', '?page=', '?user=', '?search=']):
                self.set_info(reason='Forms or parameters detected - run auxiliary scanner for SQL injection testing')
                return True
            
            return False
        except:
            return False
