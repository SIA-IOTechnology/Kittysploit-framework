#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Searches for sensitive directories present in the redirection plugin."""

from kittysploit import *
from lib.protocols.http.http_client import Http_client


class Module(Scanner, Http_client):
    __info__ = {
        'name': 'WordPress Redirection Plugin Directory Listing Detection',
        'description': 'Searches for sensitive directories present in the redirection plugin.',
        'author': ['KittySploit Team'],
        'severity': 'info',
        'tags': ['web', 'scanner', 'vulnerability', 'wordpress', 'listing', 'plugin', 'edb', 'vuln'],
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
        'references': ['https://www.exploit-db.com/ghdb/6436'],
    }

    def run(self):
        r = self.http_request(method="GET", path='/wp-content/plugins/redirection/', allow_redirects=False)
        if not r or r.status_code != 200:
            return False
        body = r.text or ""
        body_all = ('Index of', '/wp-content/plugins/redirection/',)
        if (all(m in body for m in body_all)):
            self.set_info(
                severity='info',
                reason="WordPress Redirection Plugin Directory Listing detected",
                path='/wp-content/plugins/redirection/',
            )
            return True
        return False

