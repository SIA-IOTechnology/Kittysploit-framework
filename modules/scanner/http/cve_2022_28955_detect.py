#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""D-Link DIR-816L_FW206b01 is susceptible to improper access control."""

from kittysploit import *
from lib.protocols.http.http_client import Http_client


class Module(Scanner, Http_client):
    __info__ = {
        'name': 'D-Link DIR-816L - Improper Access Control Detection',
        'description': 'D-Link DIR-816L_FW206b01 is susceptible to improper access control. An attacker can access folders folder_view.php and category_view.php and thereby possibly obtain sensitive information, modify data, and/or execute unauthorized operations.',
        'author': ['KittySploit Team'],
        'severity': 'high',
        'tags': ['web', 'scanner', 'cve', 'cve2022', 'dlink', 'exposure', 'vuln'],
        'agent': {
            'risk': 'active',
            'effects': ['network_probe'],
            'expected_requests': 2,
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
            'https://github.com/shijin0925/IOT/blob/master/DIR816/1.md',
            'https://www.dlink.com/en/security-bulletin/',
            'https://nvd.nist.gov/vuln/detail/CVE-2022-28955',
            'https://github.com/ARPSyndicate/cvemon',
            'https://github.com/ARPSyndicate/kenzer-templates',
        ],
        'cve': 'CVE-2022-28955',
    }

    def run(self):
        for path in ('/category_view.php', '/folder_view.php'):
            r = self.http_request(method="GET", path=path, allow_redirects=False)
            if not r or r.status_code != 200:
                continue
            body = r.text or ""
            body_any = ('<title>SharePort Web Access</title>',)
            if (any(m in body for m in body_any)):
                self.set_info(
                    severity='high',
                    reason="D-Link DIR-816L - Improper Access Control detected",
                    path=path,
                )
                return True
        return False

