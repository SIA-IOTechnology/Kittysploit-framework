#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Detects exposure of the Roundcube Webmail installer interface."""

from kittysploit import *
from lib.protocols.http.http_client import Http_client


class Module(Scanner, Http_client):
    __info__ = {
        'name': 'Roundcube Webmail Installer - Exposure Detection',
        'description': 'Detects exposure of the Roundcube Webmail installer interface. Public access to this installer may allow attackers to reconfigure the webmail application, potentially leading to email account compromise or the disclosure of sensitive configuration details.',
        'author': ['KittySploit Team'],
        'severity': 'high',
        'tags': ['web', 'scanner', 'misconfiguration', 'roundcube', 'webmail', 'installer', 'config', 'misconfig', 'exposure'],
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
        'references': ['https://roundcube.net/', 'https://github.com/roundcube/roundcubemail/wiki/Installation'],
    }

    def run(self):
        for path in ('/installer/', '/installer/index.php?_step=2'):
            r = self.http_request(method="GET", path=path, allow_redirects=False)
            if not r or r.status_code != 200:
                continue
            body = r.text or ""
            body_all = ('Roundcube Webmail Installer', 'wiki/Installation', 'General configuration',)
            if (all(m in body for m in body_all)):
                self.set_info(
                    severity='high',
                    reason="Roundcube Webmail Installer - Exposure detected",
                    path=path,
                )
                return True
        return False

