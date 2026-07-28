#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""WordPress Simple Ajax Chat before 20220216 is vulnerable to sensitive information disclosure."""

from kittysploit import *
from lib.protocols.http.http_client import Http_client


class Module(Scanner, Http_client):
    __info__ = {
        'name': 'WordPress Simple Ajax Chat <20220116 - Sensitive Information Disclosure vulnerability Detection',
        'description': 'WordPress Simple Ajax Chat before 20220216 is vulnerable to sensitive information disclosure. The plugin does not properly restrict access to the exported data via the sac-export.csv file, which could allow unauthenticated users to access it.',
        'author': ['KittySploit Team'],
        'severity': 'high',
        'tags': ['web', 'scanner', 'cve', 'cve2022', 'wp', 'wordpress', 'wp-plugin', 'disclosure', 'plugin-planet', 'vuln'],
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
            'https://wordpress.org/plugins/simple-ajax-chat/#developers',
            'https://patchstack.com/database/vulnerability/simple-ajax-chat/wordpress-simple-ajax-chat-plugin-20220115-sensitive-information-disclosure-vulnerability',
            'https://nvd.nist.gov/vuln/detail/CVE-2022-27849',
            'https://github.com/ARPSyndicate/cvemon',
            'https://github.com/ARPSyndicate/kenzer-templates',
        ],
        'cve': 'CVE-2022-27849',
    }

    def run(self):
        r = self.http_request(method="GET", path='/wp-content/plugins/simple-ajax-chat/sac-export.csv', allow_redirects=False)
        if not r or r.status_code != 200:
            return False
        body = r.text or ""
        headers = "\n".join(f"{k}: {v}" for k, v in r.headers.items())
        body_all = ('"Chat Log"', '"User IP"', '"User ID"',)
        header_any = ('text/csv',)
        if (all(m in body for m in body_all)) and (any(m in headers for m in header_any)):
            self.set_info(
                severity='high',
                reason="WordPress Simple Ajax Chat <20220116 - Sensitive Information Disclosure vulnerability detected",
                path='/wp-content/plugins/simple-ajax-chat/sac-export.csv',
            )
            return True
        return False

