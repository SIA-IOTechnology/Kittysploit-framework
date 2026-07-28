#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""The exposure of the KACE Systems Management Appliance’s installer interface through the /common/setup."""

from kittysploit import *
from lib.protocols.http.http_client import Http_client


class Module(Scanner, Http_client):
    __info__ = {
        'name': 'KACE Systems Management Appliance - Installer Detection',
        'description': 'The exposure of the KACE Systems Management Appliance’s installer interface through the /common/setup.php endpoint allowed unauthorized access to the system setup wizard. This interface was publicly accessible when it should have been restricted, potentially granting attackers the ability to initiate or manipulate the setup process, leading to system compromise or unauthorized configuration changes.',
        'author': ['KittySploit Team'],
        'severity': 'high',
        'tags': ['web', 'scanner', 'misconfiguration', 'kace', 'sma', 'installer', 'exposure', 'quest', 'vuln'],
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
    }

    def run(self):
        r = self.http_request(method="GET", path='/common/setup.php', allow_redirects=False)
        if not r or r.status_code != 200:
            return False
        body = (r.text or "").lower()
        body_all = ('initial setup', 'setup_wizard', 'kace',)
        if (all(m in body for m in body_all)):
            self.set_info(
                severity='high',
                reason="KACE Systems Management Appliance - Installer detected",
                path='/common/setup.php',
            )
            return True
        return False

