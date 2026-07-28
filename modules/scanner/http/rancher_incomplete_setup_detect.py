#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Detected Rancher installation was found with an incomplete first-time setup."""

from kittysploit import *
from lib.protocols.http.http_client import Http_client


class Module(Scanner, Http_client):
    __info__ = {
        'name': 'Rancher - Incomplete Setup Exposure Detection',
        'description': 'Detected Rancher installation was found with an incomplete first-time setup. The bootstrap login page was publicly accessible at /dashboard/auth/login, indicating an unconfigured instance that could have been targeted for unauthorized setup completion.',
        'author': ['KittySploit Team'],
        'severity': 'low',
        'tags': ['web', 'scanner', 'misconfiguration', 'rancher', 'misconfig', 'exposure'],
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
        'references': ['https://rancher.com/docs/rancher/v2.6/en/installation/'],
    }

    def run(self):
        r = self.http_request(method="GET", path='/v3/settings/first-login', allow_redirects=False)
        if not r or r.status_code != 200:
            return False
        body = r.text or ""
        body_all = ('"value":"true"', '"name":"first-login"',)
        if (all(m in body for m in body_all)):
            self.set_info(
                severity='low',
                reason="Rancher - Incomplete Setup Exposure detected",
                path='/v3/settings/first-login',
            )
            return True
        return False

