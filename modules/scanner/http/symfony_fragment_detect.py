#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Symfony servers support a "/_fragment" command that allows clients to provide custom PHP commands and return t."""

from kittysploit import *
from lib.protocols.http.http_client import Http_client


class Module(Scanner, Http_client):
    __info__ = {
        'name': 'Symfony _fragment - Detect',
        'description': 'Symfony servers support a "/_fragment" command that allows clients to provide custom PHP commands and return the HTML output.',
        'author': ['KittySploit Team'],
        'severity': 'info',
        'tags': ['web', 'scanner', 'misconfiguration', 'config', 'exposure', 'symfony', 'misconfig', 'vuln'],
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
                'suggested_followups': [],
            },
        },
        'references': [
            'https://portswigger.net/daily-swig/symfony-based-websites-open-to-rce-attack-research-finds',
            'https://medium.com/@m4cddr/how-i-got-rce-in-10-websites-26dd87441f22',
            'https://al1z4deh.medium.com/how-i-hacked-28-sites-at-once-rce-5458211048d5',
            'https://github.com/ambionics/symfony-exploits',
        ],
    }

    def run(self):
        path = '/_fragment'
        r = self.http_request(method='GET', path=path, allow_redirects=False)
        if not r or r.status_code != 403:
            return False
        body = r.text or ""
        body_any = ('Symfony', '403 Forbidden',)
        if any(m in body for m in body_any):
            self.set_info(
                severity='info',
                reason='Symfony _fragment detected',
                path=path,
            )
            return True
        return False

