#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""ConnectWise ScreenConnect CVE-2024-1709 (SetupWizard auth bypass) detection."""

import secrets

from kittysploit import *
from lib.protocols.http.http_client import Http_client


class Module(Scanner, Http_client):
    __info__ = {
        'name': 'ConnectWise ScreenConnect CVE-2024-1709 Detection',
        'description': (
            'Detects CVE-2024-1709 authentication bypass by accessing '
            '/SetupWizard.aspx/<random> without authentication.'
        ),
        'author': ['KittySploit Team'],
        'severity': 'critical',
        'tags': [
            'web', 'scanner', 'cve', 'cve2024', 'screenconnect', 'connectwise',
            'auth-bypass', 'kev', 'vkev', 'vuln',
        ],
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
                    {'capability': 'admin_surface', 'from_detail': ''},
                ],
                'consumes_capabilities': [],
                'option_bindings': {},
                'suggested_followups': [],
            },
        },
        'references': [
            'https://nvd.nist.gov/vuln/detail/CVE-2024-1709',
            'https://www.huntress.com/blog/a-catastrophe-for-control-understanding-the-screenconnect-authentication-bypass',
            'https://www.connectwise.com/company/trust/security-bulletins/connectwise-screenconnect-23.9.8',
        ],
        'cve': 'CVE-2024-1709',
    }

    def run(self):
        token = secrets.token_hex(5)
        path = f'/SetupWizard.aspx/{token}'
        r = self.http_request(method='GET', path=path, allow_redirects=False)
        if not r or r.status_code != 200:
            return False
        body = r.text or ''
        if 'SetupWizardPage' not in body or 'ContentPanel SetupWizard' not in body:
            return False
        self.set_info(
            severity='critical',
            reason='ScreenConnect CVE-2024-1709 SetupWizard auth bypass confirmed',
            path=path,
            evidence='SetupWizardPage + ContentPanel SetupWizard',
        )
        return True
