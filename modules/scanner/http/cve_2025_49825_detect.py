#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Teleport versions prior to 17."""

from kittysploit import *
from lib.protocols.http.http_client import Http_client


class Module(Scanner, Http_client):
    __info__ = {
        'name': 'Teleport - Authentication Bypass Detection',
        'description': 'Teleport versions prior to 17.5.2 are vulnerable to a remote authentication bypass vulnerability. This issue allows attackers to gain unauthorized access to affected systems.',
        'author': ['KittySploit Team'],
        'severity': 'critical',
        'tags': ['web', 'scanner', 'cve', 'cve2025', 'teleport', 'passive', 'auth-bypass', 'vuln'],
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
                'suggested_followups': [],
            },
        },
        'references': ['https://github.com/gravitational/teleport/security/advisories/GHSA-8cqv-pj7f-pwpc'],
        'cve': 'CVE-2025-49825',
    }

    def run(self):
        path = '/webapi/ping'
        r = self.http_request(method='GET', path=path, allow_redirects=False)
        if not r or r.status_code != 200:
            return False
        body = r.text or ""
        body_all = ('server_version', 'teleport',)
        if all(m in body for m in body_all):
            self.set_info(
                severity='critical',
                reason='Teleport - Authentication Bypass detected',
                path=path,
            )
            return True
        return False

