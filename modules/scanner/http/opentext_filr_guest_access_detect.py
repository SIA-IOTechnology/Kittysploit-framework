#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""OpenText Filr (formerly Micro Focus/Novell Filr) had guest access enabled, allowing unauthenticated users to a."""

from kittysploit import *
from lib.protocols.http.http_client import Http_client


class Module(Scanner, Http_client):
    __info__ = {
        'name': 'OpenText Filr - Guest Access Enabled Detection',
        'description': 'OpenText Filr (formerly Micro Focus/Novell Filr) had guest access enabled, allowing unauthenticated users to access the system as a Guest, exposing GuestUser: \'true\' and an "Enter as Guest" option on the SSF login page.',
        'author': ['KittySploit Team'],
        'severity': 'medium',
        'tags': ['web', 'scanner', 'misconfiguration', 'misconfig', 'opentext', 'filr', 'exposure'],
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
            'https://www.microfocus.com/documentation/filr/filr-23.2/filr-admin/access.html',
            'https://www.microfocus.com/documentation/filr/filr-23.2/filr-inst/bjm9tb7.html',
            'https://opentext.com/products/filr',
        ],
    }

    def run(self):
        r = self.http_request(method="GET", path='/ssf/a/do?p_name=ss_forum&p_action=1&action=__login', allow_redirects=True)
        if not r or r.status_code != 200:
            return False
        body = r.text or ""
        body_any = ('Filr', 'filr', 'Vibe',)
        body_all = ('GuestUser', 'true',)
        if (any(m in body for m in body_any)) and (all(m in body for m in body_all)):
            self.set_info(
                severity='medium',
                reason="OpenText Filr - Guest Access Enabled detected",
                path='/ssf/a/do?p_name=ss_forum&p_action=1&action=__login',
            )
            return True
        return False

