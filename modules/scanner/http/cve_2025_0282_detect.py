#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Ivanti Connect Secure < 22."""

from kittysploit import *
from lib.protocols.http.http_client import Http_client


class Module(Scanner, Http_client):
    __info__ = {
        'name': 'Ivanti Connect Secure - Stack-based Buffer Overflow Detection',
        'description': 'Ivanti Connect Secure < 22.7R2.5, Ivanti Policy Secure < 22.7R1.2, and Ivanti Neurons for ZTA gateways < 22.7R2.3 contain a stack-based buffer overflow in the clientCapabilities parameter handling. This vulnerability allows remote unauthenticated attackers to execute arbitrary code through IF-T TLS requests.',
        'author': ['KittySploit Team'],
        'severity': 'critical',
        'tags': ['web', 'scanner', 'cve', 'cve2025', 'ivanti', 'rce', 'buffer-overflow', 'passive', 'kev', 'vkev', 'vuln'],
        'agent': {
            'risk': 'active',
            'effects': ['network_probe'],
            'expected_requests': 3,
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
            'https://forums.ivanti.com/s/article/Security-Advisory-Ivanti-Connect-Secure-Policy-Secure-ZTA-Gateways-CVE-2025-0282-CVE-2025-0283',
            'https://labs.watchtowr.com/exploitation-walkthrough-and-techniques-ivanti-connect-secure-rce-cve-2025-0282/',
            'https://cloud.google.com/blog/topics/threat-intelligence/ivanti-connect-secure-vpn-zero-day',
            'https://nvd.nist.gov/vuln/detail/CVE-2025-0282',
        ],
        'cve': 'CVE-2025-0282',
    }

    def run(self):
        for path in ('/dana-na/auth/url_default/welcome.cgi', '/dana-na/auth/url_6/welcome.cgi', '/dana/home/index.cgi'):
            r = self.http_request(method='GET', path=path, allow_redirects=False)
            if not r or r.status_code != 200:
                continue
            body = r.text or ""
            body_any = ('Ivanti', 'Connect Secure', 'Policy Secure', 'Neurons for ZTA',)
            if any(m in body for m in body_any):
                self.set_info(
                    severity='critical',
                    reason='Ivanti Connect Secure - Stack-based Buffer Overflow detected',
                    path=path,
                )
                return True
        return False

