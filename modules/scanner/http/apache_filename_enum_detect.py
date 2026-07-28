#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""If the client provides an invalid Accept header, the server will respond with a 406 Not Acceptable error conta."""

from kittysploit import *
from lib.protocols.http.http_client import Http_client


class Module(Scanner, Http_client):
    __info__ = {
        'name': 'Apache Filename Enumeration Detection',
        'description': 'If the client provides an invalid Accept header, the server will respond with a 406 Not Acceptable error containing a pseudo directory listing.',
        'author': ['KittySploit Team'],
        'severity': 'low',
        'tags': ['web', 'scanner', 'misconfiguration', 'apache', 'misconfig', 'hackerone', 'vuln'],
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
            'https://hackerone.com/reports/210238',
            'https://www.acunetix.com/vulnerabilities/web/apache-mod_negotiation-filename-bruteforcing/',
        ],
    }

    def run(self):
        r = self.http_request(method="GET", path='/index', allow_redirects=False)
        if not r or r.status_code != 406:
            return False
        body = r.text or ""
        body_all = ('Not Acceptable', 'Available variants:', '<address>Apache Server at',)
        if (all(m in body for m in body_all)):
            self.set_info(
                severity='low',
                reason="Apache Filename Enumeration detected",
                path='/index',
            )
            return True
        return False

