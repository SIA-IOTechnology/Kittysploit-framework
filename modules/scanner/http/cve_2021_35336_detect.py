#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Tieline IP Audio Gateway 2."""

from kittysploit import *
from lib.protocols.http.http_client import Http_client


class Module(Scanner, Http_client):
    __info__ = {
        'name': 'Tieline IP Audio Gateway <=2.6.4.8 - Unauthorized Remote Admin Panel Access Detection',
        'description': 'Tieline IP Audio Gateway 2.6.4.8 and below is affected by a vulnerability in the web administrative interface that could allow an unauthenticated user to access a sensitive part of the system with a high privileged account.',
        'author': ['KittySploit Team'],
        'severity': 'critical',
        'tags': ['web', 'scanner', 'cve', 'cve2021', 'tieline', 'default-login', 'vuln'],
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
            'https://pratikkhalane91.medium.com/use-of-default-credentials-to-unauthorised-remote-access-of-internal-panel-of-tieline-c1ffe3b3757c',
            'https://nvd.nist.gov/vuln/detail/CVE-2021-35336',
            'https://github.com/ARPSyndicate/cvemon',
            'https://github.com/ARPSyndicate/kenzer-templates',
        ],
        'cve': 'CVE-2021-35336',
    }

    def run(self):
        r = self.http_request(method="GET", path='/api/get_device_details', allow_redirects=False)
        if not r or r.status_code != 200:
            return False
        body = r.text or ""
        headers = "\n".join(f"{k}: {v}" for k, v in r.headers.items())
        body_all = ('<SERIAL>', '<VERSION>',)
        header_any = ('text/xml',)
        if (all(m in body for m in body_all)) and (any(m in headers for m in header_any)):
            self.set_info(
                severity='critical',
                reason="Tieline IP Audio Gateway <=2.6.4.8 - Unauthorized Remote Admin Panel Access detected",
                path='/api/get_device_details',
            )
            return True
        return False

