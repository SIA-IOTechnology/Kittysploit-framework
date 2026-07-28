#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Axiom is a dynamic infrastructure framework to efficiently work with multi-cloud environments."""

from kittysploit import *
from lib.protocols.http.http_client import Http_client


class Module(Scanner, Http_client):
    __info__ = {
        'name': 'DigitalOcean Key Exposure via Axiom Detection',
        'description': 'Axiom is a dynamic infrastructure framework to efficiently work with multi-cloud environments.',
        'author': ['KittySploit Team'],
        'severity': 'critical',
        'tags': ['web', 'scanner', 'exposure', 'axiom', 'digitalocean', 'key', 'vuln'],
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
        'references': ['https://github.com/pry0cc/axiom'],
    }

    def run(self):
        r = self.http_request(method="GET", path='/.axiom/accounts/do.json', allow_redirects=False)
        if not r or r.status_code != 200:
            return False
        body = r.text or ""
        body_all = ('"do_key"', '"region"', '"provider"',)
        if (all(m in body for m in body_all)):
            self.set_info(
                severity='critical',
                reason="DigitalOcean Key Exposure via Axiom detected",
                path='/.axiom/accounts/do.json',
            )
            return True
        return False

