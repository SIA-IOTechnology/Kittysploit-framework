#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""The application is vulnerable to sensitive information disclosure vulnerability."""

from kittysploit import *
from lib.protocols.http.http_client import Http_client


class Module(Scanner, Http_client):
    __info__ = {
        'name': 'RED-V Super Digital Signage System RXV-A740R - Log Information Disclosure Detection',
        'description': "The application is vulnerable to sensitive information disclosure vulnerability. An unauthenticated attacker can visit several endpoints and disclose the webserver's log file list containing sensitive system resources and debug log information running on the device.",
        'author': ['KittySploit Team'],
        'severity': 'medium',
        'tags': ['web', 'scanner', 'exposure', 'redv', 'log', 'disclosure', 'vuln'],
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
        'references': ['https://www.zeroscience.mk/en/vulnerabilities/ZSL-2020-5609.php'],
    }

    def run(self):
        r = self.http_request(method="GET", path='/downloader.log', allow_redirects=False)
        if not r or r.status_code != 200:
            return False
        body = r.text or ""
        body_any = ('text/plain',)
        body_all = ('Log file', '[LogParser]', '[INFO]',)
        if (any(m in body for m in body_any)) and (all(m in body for m in body_all)):
            self.set_info(
                severity='medium',
                reason="RED-V Super Digital Signage System RXV-A740R - Log Information Disclosure detected",
                path='/downloader.log',
            )
            return True
        return False

