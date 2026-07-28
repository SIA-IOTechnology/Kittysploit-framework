#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Icinga Web 2 installer/setup wizard is publicly accessible."""

from kittysploit import *
from lib.protocols.http.http_client import Http_client


class Module(Scanner, Http_client):
    __info__ = {
        'name': 'Icinga Web 2 Installer Exposure Detection',
        'description': 'Icinga Web 2 installer/setup wizard is publicly accessible. The setup page at /icingaweb2/setup exposes the configuration wizard which guides through full application configuration including database credentials, authentication backends, and admin account creation. While a setup token is required to proceed, the exposure of the installer itself is a serious misconfiguration that signals an incomplete or improperly secured installation.',
        'author': ['KittySploit Team'],
        'severity': 'high',
        'tags': ['web', 'scanner', 'misconfiguration', 'icinga', 'exposure', 'misconfig', 'installer'],
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
        'references': ['https://icinga.com/docs/icinga-web/latest/doc/02-Installation/'],
    }

    def run(self):
        for path in ('/icingaweb2/setup', '/setup'):
            r = self.http_request(method="GET", path=path, allow_redirects=False)
            if not r or r.status_code != 200:
                continue
            body = r.text or ""
            body_all = ('Welcome to the configuration of Icinga Web 2', 'Setup Token',)
            if (all(m in body for m in body_all)):
                self.set_info(
                    severity='high',
                    reason="Icinga Web 2 Installer Exposure detected",
                    path=path,
                )
                return True
        return False

