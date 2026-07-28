#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Simple 301 Redirects WordPress plugin contains a full path disclosure vulnerability due to improper access res."""

from kittysploit import *
from lib.protocols.http.http_client import Http_client


class Module(Scanner, Http_client):
    __info__ = {
        'name': 'Simple 301 Redirects - Full Path Disclosure Detection',
        'description': 'Simple 301 Redirects WordPress plugin contains a full path disclosure vulnerability due to improper access restrictions in its source files, allowing unauthenticated attackers to retrieve full server paths and aiding exploitation.',
        'author': ['KittySploit Team'],
        'severity': 'low',
        'tags': ['web', 'scanner', 'misconfiguration', 'debug', 'wordpress', 'wp', 'wp-plugin', 'simple-301-redirects', 'fpd'],
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
        'references': ['https://wordpress.org/plugins/simple-301-redirects/'],
    }

    def run(self):
        r = self.http_request(method="GET", path='/plugins/simple-301-redirects/wp-simple-301-redirects.php', allow_redirects=False)
        if not r or r.status_code != 200:
            return False
        body = r.text or ""
        body_all = ('Fatal error', 'Uncaught Error', 'simple-301-redirects',)
        if (all(m in body for m in body_all)):
            self.set_info(
                severity='low',
                reason="Simple 301 Redirects - Full Path Disclosure detected",
                path='/plugins/simple-301-redirects/wp-simple-301-redirects.php',
            )
            return True
        return False

