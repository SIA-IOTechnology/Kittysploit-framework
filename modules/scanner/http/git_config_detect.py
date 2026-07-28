#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Git configuration was detected via the pattern /."""

from kittysploit import *
from lib.protocols.http.http_client import Http_client


class Module(Scanner, Http_client):
    __info__ = {
        'name': 'Git Configuration - Detect',
        'description': 'Git configuration was detected via the pattern /.git/config and log file on passed URLs.',
        'author': ['KittySploit Team'],
        'severity': 'medium',
        'tags': ['web', 'scanner', 'exposure', 'config', 'git', 'vuln'],
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
        r = self.http_request(method="GET", path='/.git/config', allow_redirects=False)
        if not r or r.status_code != 200:
            return False
        if self.is_same_as_index(r, path='/.git/config'):
            return False
        body = (r.text or "").lower()
        # Require real git config markers — HTML catch-alls must not match.
        if '[core]' in body or '[credentials]' in body or '[remote' in body:
            if '<html' in body or '<!doctype' in body:
                return False
            self.set_info(
                severity='medium',
                reason="Git Configuration detected",
                path='/.git/config',
            )
            return True
        return False

