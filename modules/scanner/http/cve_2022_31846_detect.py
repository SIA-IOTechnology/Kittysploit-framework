#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""WAVLINK WN535 G3 M35G3R."""

from kittysploit import *
from lib.protocols.http.http_client import Http_client


class Module(Scanner, Http_client):
    __info__ = {
        'name': 'WAVLINK WN535 G3 - Information Disclosure Detection',
        'description': 'WAVLINK WN535 G3 M35G3R.V5030.180927 is susceptible to information disclosure in the live_mfg.shtml page. An attacker can obtain sensitive router information via the exec cmd function and possibly obtain additional sensitive information, modify data, and/or execute unauthorized operations.',
        'author': ['KittySploit Team'],
        'severity': 'high',
        'tags': ['web', 'scanner', 'cve', 'cve2022', 'wavlink', 'exposure', 'vuln'],
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
            'https://github.com/pghuanghui/CVE_Request/blob/main/WAVLINK%20WN535%20G3__live_mfg.md',
            'https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2022-30489',
            'https://nvd.nist.gov/vuln/detail/CVE-2022-31846',
            'https://github.com/ARPSyndicate/cvemon',
            'https://github.com/ARPSyndicate/kenzer-templates',
        ],
        'cve': 'CVE-2022-31846',
    }

    def run(self):
        r = self.http_request(method="GET", path='/live_mfg.shtml', allow_redirects=False)
        if not r or r.status_code != 200:
            return False
        body = r.text or ""
        body_all = ('Model=', 'DefaultIP=', 'LOGO1=',)
        if (all(m in body for m in body_all)):
            self.set_info(
                severity='high',
                reason="WAVLINK WN535 G3 - Information Disclosure detected",
                path='/live_mfg.shtml',
            )
            return True
        return False

