#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Zoho ManageEngine OpManager before 12."""

from kittysploit import *
from lib.protocols.http.http_client import Http_client


class Module(Scanner, Http_client):
    __info__ = {
        'name': 'Zoho ManageEngine OpManager < 12.5.329 - Remote Code Execution Detection',
        'description': 'Zoho ManageEngine OpManager before 12.5.329 contains a remote code execution caused by a general bypass in the deserialization class, letting unauthenticated attackers execute arbitrary code, exploit requires no authentication',
        'author': ['KittySploit Team'],
        'severity': 'critical',
        'tags': ['web', 'scanner', 'cve', 'cve2021', 'deserialization', 'rce', 'opmanager', 'passive', 'vkev'],
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
        'references': [
            'http://packetstormsecurity.com/files/164231/ManageEngine-OpManager-SumPDU-Java-Deserialization.html',
            'https://nvd.nist.gov/vuln/detail/CVE-2021-3287',
        ],
        'cve': 'CVE-2021-3287',
    }

    def run(self):
        path = '/'
        r = self.http_request(method='GET', path=path, allow_redirects=True)
        if not r or r.status_code != 200:
            return False
        body = r.text or ""
        body_any = ('ManageEngine',)
        if any(m in body for m in body_any):
            self.set_info(
                severity='critical',
                reason='Zoho ManageEngine OpManager < 12.5.329 - Remote Code Execution detected',
                path=path,
            )
            return True
        return False

