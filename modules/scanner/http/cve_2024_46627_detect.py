#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Incorrect access control in BECN DATAGERRY v2."""

from kittysploit import *
from lib.protocols.http.http_client import Http_client


class Module(Scanner, Http_client):
    __info__ = {
        'name': 'DATAGERRY - REST API Auth Bypass Detection',
        'description': 'Incorrect access control in BECN DATAGERRY v2.2 allows attackers to execute arbitrary commands via crafted web requests.',
        'author': ['KittySploit Team'],
        'severity': 'critical',
        'tags': ['web', 'scanner', 'cve', 'cve2024', 'becon', 'datagerry', 'unauth', 'auth-bypass', 'vuln'],
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
            'https://nvd.nist.gov/vuln/detail/CVE-2024-46627',
            'https://daly.wtf/cve-2024-46627-incorrect-access-control-in-becn-datagerry-v2-2-allows-attackers-to-execute-arbitrary-commands-via-crafted-web-requests/',
            'https://datagerry.com/',
            'https://github.com/DATAGerry/',
            'https://github.com/d4lyw/CVE-2024-46627',
        ],
        'cve': 'CVE-2024-46627',
    }

    def run(self):
        path = '/rest/users/1/settings/'
        r = self.http_request(method='GET', path=path, allow_redirects=False)
        if not r or r.status_code != 200:
            return False
        body = r.text or ""
        content_type = r.headers.get("Content-Type") or r.headers.get("content-type") or ""
        body_all = ('"response_type":', '"model":', '"time":',)
        ctype_any = ('application/json',)
        if (all(m in body for m in body_all)) and (any(m in content_type for m in ctype_any)):
            self.set_info(
                severity='critical',
                reason='DATAGERRY - REST API Auth Bypass detected',
                path=path,
            )
            return True
        return False

