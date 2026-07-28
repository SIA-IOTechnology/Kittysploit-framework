#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""In phpIPAM 1."""

from kittysploit import *
from lib.protocols.http.http_client import Http_client


class Module(Scanner, Http_client):
    __info__ = {
        'name': 'PHPIPAM <v1.5.1 - Missing Authorization Detection',
        'description': 'In phpIPAM 1.5.1, an unauthenticated user could download the list of high-usage IP subnets that contains sensitive information such as a subnet description, IP ranges, and usage rates via find_full_subnets.php endpoint. The bug lies in the fact that find_full_subnets.php does not verify if the user is authorized to access the data, and if the script was started from a command line.',
        'author': ['KittySploit Team'],
        'severity': 'medium',
        'tags': ['web', 'scanner', 'cve', 'cve2023', 'php', 'phpipam', 'unauth', 'vuln'],
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
        'references': ['https://github.com/phpipam/phpipam/commit/1960bd24e8a55796da066237cf11272c44bb1cc4'],
        'cve': 'CVE-2023-0678',
    }

    def run(self):
        r = self.http_request(method="GET", path='/functions/scripts/find_full_subnets.php', allow_redirects=False)
        if not r or r.status_code != 200:
            return False
        body = r.text or ""
        body_all = ('Array', '[subnet]', '[description]',)
        if (all(m in body for m in body_all)):
            self.set_info(
                severity='medium',
                reason="PHPIPAM <v1.5.1 - Missing Authorization detected",
                path='/functions/scripts/find_full_subnets.php',
            )
            return True
        return False

