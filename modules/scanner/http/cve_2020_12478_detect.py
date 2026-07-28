#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""TeamPass 2."""

from kittysploit import *
from lib.protocols.http.http_client import Http_client


class Module(Scanner, Http_client):
    __info__ = {
        'name': 'TeamPass 2.1.27.36 - Improper Authentication Detection',
        'description': 'TeamPass 2.1.27.36 is susceptible to improper authentication. An attacker can retrieve files from the TeamPass web root, which may include backups or LDAP debug files, and therefore possibly obtain sensitive information, modify data, and/or execute unauthorized operations.',
        'author': ['KittySploit Team'],
        'severity': 'high',
        'tags': ['web', 'scanner', 'cve', 'cve2020', 'teampass', 'exposure', 'unauth', 'vuln'],
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
            'https://github.com/nilsteampassnet/TeamPass/issues/2764',
            'https://nvd.nist.gov/vuln/detail/CVE-2020-12478',
            'https://github.com/ARPSyndicate/cvemon',
            'https://github.com/ARPSyndicate/kenzer-templates',
            'https://github.com/StarCrossPortal/scalpel',
        ],
        'cve': 'CVE-2020-12478',
    }

    def run(self):
        r = self.http_request(method="GET", path='/files/ldap.debug.txt', allow_redirects=False)
        if not r or r.status_code != 200:
            return False
        body = r.text or ""
        headers = "\n".join(f"{k}: {v}" for k, v in r.headers.items())
        body_any = ('Get all LDAP params',)
        header_any = ('text/plain',)
        if (any(m in body for m in body_any)) and (any(m in headers for m in header_any)):
            self.set_info(
                severity='high',
                reason="TeamPass 2.1.27.36 - Improper Authentication detected",
                path='/files/ldap.debug.txt',
            )
            return True
        return False

