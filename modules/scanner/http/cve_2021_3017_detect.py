#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Intelbras WIN 300 and WRN 342 devices through 2021-01-04 allows remote attackers to discover credentials by re."""

from kittysploit import *
from lib.protocols.http.http_client import Http_client


class Module(Scanner, Http_client):
    __info__ = {
        'name': 'Intelbras WIN 300/WRN 342 - Credentials Disclosure Detection',
        'description': 'Intelbras WIN 300 and WRN 342 devices through 2021-01-04 allows remote attackers to discover credentials by reading the def_wirelesspassword line in the HTML source code.',
        'author': ['KittySploit Team'],
        'severity': 'high',
        'tags': ['web', 'scanner', 'cve', 'cve2021', 'exposure', 'router', 'intelbras', 'vuln'],
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
            'https://nvd.nist.gov/vuln/detail/CVE-2021-3017',
            'https://pastebin.com/cTYTf0Yn',
            'https://github.com/bigblackhat/oFx',
            'https://github.com/openx-org/BLEN',
            'https://github.com/Miraitowa70/POC-Notes',
        ],
        'cve': 'CVE-2021-3017',
    }

    def run(self):
        r = self.http_request(method="GET", path='/index.asp', allow_redirects=False)
        if not r or r.status_code != 200:
            return False
        body = r.text or ""
        body_all = ('def_wirelesspassword =', '<title>Roteador Wireless</title>',)
        if (all(m in body for m in body_all)):
            self.set_info(
                severity='high',
                reason="Intelbras WIN 300/WRN 342 - Credentials Disclosure detected",
                path='/index.asp',
            )
            return True
        return False

