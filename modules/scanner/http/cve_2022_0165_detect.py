#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""WordPress Page Builder KingComposer 2."""

import re
from kittysploit import *
from lib.protocols.http.http_client import Http_client


class Module(Scanner, Http_client):
    __info__ = {
        'name': 'WordPress Page Builder KingComposer <=2.9.6 - Open Redirect Detection',
        'description': 'WordPress Page Builder KingComposer 2.9.6 and prior does not validate the id parameter before redirecting the user to it via the kc_get_thumbn AJAX action (which is available to both unauthenticated and authenticated users).',
        'author': ['KittySploit Team'],
        'severity': 'medium',
        'tags': ['web', 'scanner', 'cve', 'cve2022', 'wp-plugin', 'redirect', 'wordpress', 'wp', 'wpscan', 'king-theme', 'vuln'],
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
            'https://wpscan.com/vulnerability/906d0c31-370e-46b4-af1f-e52fbddd00cb',
            'https://nvd.nist.gov/vuln/detail/CVE-2022-0165',
            'https://github.com/ARPSyndicate/cvemon',
            'https://github.com/ARPSyndicate/kenzer-templates',
            'https://github.com/K3ysTr0K3R/CVE-2022-0165-EXPLOIT',
        ],
        'cve': 'CVE-2022-0165',
    }

    def run(self):
        r = self.http_request(method="GET", path='/wp-admin/admin-ajax.php?action=kc_get_thumbn&id=https://interact.sh', allow_redirects=False)
        if not r or r.status_code != 200:
            return False
        headers = "\n".join(f"{k}: {v}" for k, v in r.headers.items())
        header_regexes = ('(?m)^(?:Location\\s*?:\\s*?)(?:https?://|//)(?:[a-zA-Z0-9\\-_\\.@]*)interact\\.sh.*$',)
        if (any(re.search(rx, headers, 0) for rx in header_regexes)):
            self.set_info(
                severity='medium',
                reason="WordPress Page Builder KingComposer <=2.9.6 - Open Redirect detected",
                path='/wp-admin/admin-ajax.php?action=kc_get_thumbn&id=https://interact.sh',
            )
            return True
        return False

