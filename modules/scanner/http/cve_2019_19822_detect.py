#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""A certain router administration interface using Realtek APMIB (e."""

from kittysploit import *
from lib.protocols.http.http_client import Http_client


class Module(Scanner, Http_client):
    __info__ = {
        'name': 'TOTOLINK/Realtek Routers - Information Disclosure Detection',
        'description': 'A certain router administration interface using Realtek APMIB (e.g., on TOTOLINK models) allows unauthenticated remote attackers to disclose the entire router configuration, including sensitive credentials, via accessing the "config.dat" file. Affected devices include TOTOLINK A3002RU through 2.0.0, A702R through 2.1.3, N301RT through 2.1.6, N302R through 3.4.0, N300RT through 3.4.0, N200RE through 4.0.0, N150RT through 3.4.0, N100RE through 3.4.0, and other Realtek SDK-based devices.',
        'author': ['KittySploit Team'],
        'severity': 'high',
        'tags': ['web', 'scanner', 'cve', 'cve2019', 'totolink', 'realtek', 'information-disclosure', 'config', 'boa'],
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
            'http://packetstormsecurity.com/files/156083/Realtek-SDK-Information-Disclosure-Code-Execution.html',
            'https://nvd.nist.gov/vuln/detail/CVE-2019-19822',
        ],
        'cve': 'CVE-2019-19822',
    }

    def run(self):
        r = self.http_request(method="GET", path='/config.dat', allow_redirects=False)
        if not r or r.status_code != 200:
            return False
        body = (r.text or "").lower()
        body_any = ('text/plain', 'boa', 'bytes',)
        if (any(m in body for m in body_any)):
            self.set_info(
                severity='high',
                reason="TOTOLINK/Realtek Routers - Information Disclosure detected",
                path='/config.dat',
            )
            return True
        return False

