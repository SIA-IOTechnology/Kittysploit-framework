#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Detected public user registration is enabled on a Seafile instance."""

from kittysploit import *
from lib.protocols.http.http_client import Http_client


class Module(Scanner, Http_client):
    __info__ = {
        'name': 'Seafile - Public Registration Enabled Detection',
        'description': 'Detected public user registration is enabled on a Seafile instance.',
        'author': ['KittySploit Team'],
        'severity': 'info',
        'tags': ['web', 'scanner', 'misconfiguration', 'misconfig', 'seafile', 'registration', 'exposure'],
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
        'references': ['https://forum.seafile.com/t/seafile-disable-email-registration-for-users/4957'],
    }

    def run(self):
        r = self.http_request(method="GET", path='/accounts/register/', allow_redirects=False)
        if not r or r.status_code != 200:
            return False
        body = r.text or ""
        body_all = ('id_email', 'id_password1', 'csrfmiddlewaretoken', 'seafile-ui.css', 'SEAFILE_GLOBAL',)
        if (all(m in body for m in body_all)):
            self.set_info(
                severity='info',
                reason="Seafile - Public Registration Enabled detected",
                path='/accounts/register/',
            )
            return True
        return False

