#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""An issue in Ruijie RG-NBS2009G-P RGOS v."""

from kittysploit import *
from lib.protocols.http.http_client import Http_client


class Module(Scanner, Http_client):
    __info__ = {
        'name': 'Ruijie RG-NBS2009G-P - Improper Authentication Detection',
        'description': 'An issue in Ruijie RG-NBS2009G-P RGOS v.10.4(1)P2 Release(9736) allows a remote attacker to gain privileges via the system/config_menu.htm.',
        'author': ['KittySploit Team'],
        'severity': 'critical',
        'tags': ['web', 'scanner', 'cve', 'ruijie', 'cve2024', 'exposure', 'bac', 'vuln'],
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
            'https://github.com/zty-1995/RG-NBS2009G-P-switch/tree/main/Unauthorized%20Access%20Vulnerability',
            'https://gist.github.com/zty-1995/7a5e3ad0eb3b6c44db1a6eb4092893d3',
            'https://nvd.nist.gov/vuln/detail/CVE-2024-24116',
        ],
        'cve': 'CVE-2024-24116',
    }

    def run(self):
        r = self.http_request(method="GET", path='/system/config_menu.htm', allow_redirects=False)
        if not r or r.status_code != 200:
            return False
        body = r.text or ""
        body_all = ('configManage.asp', 'reinitIframe()',)
        if (all(m in body for m in body_all)):
            self.set_info(
                severity='critical',
                reason="Ruijie RG-NBS2009G-P - Improper Authentication detected",
                path='/system/config_menu.htm',
            )
            return True
        return False

