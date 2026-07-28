#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""The /rest/rights/ REST API endpoint in Becon DATAGerry through 2."""

from kittysploit import *
from lib.protocols.http.http_client import Http_client


class Module(Scanner, Http_client):
    __info__ = {
        'name': 'DATAGERRY - Improper Access Control Detection',
        'description': 'The /rest/rights/ REST API endpoint in Becon DATAGerry through 2.2.0 contains an Incorrect Access Control vulnerability. An attacker can remotely access this endpoint without authentication, leading to unauthorized disclosure of sensitive information.',
        'author': ['KittySploit Team'],
        'severity': 'high',
        'tags': ['web', 'scanner', 'cve', 'cve2024', 'datagerry', 'auth-bypass', 'vkev', 'vuln'],
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
            'https://medium.com/@0xbytehunter/my-first-cve-discovery-of-broken-access-control-in-the-datagerry-platform-7b0404f88a43',
            'https://github.com/0xByteHunter/CVE-2024-50967',
            'https://nvd.nist.gov/vuln/detail/CVE-2024-50967',
        ],
        'cve': 'CVE-2024-50967',
    }

    def run(self):
        path = '/rest/rights/'
        r = self.http_request(method='GET', path=path, allow_redirects=False)
        if not r or r.status_code != 200:
            return False
        body = r.text or ""
        content_type = r.headers.get("Content-Type") or r.headers.get("content-type") or ""
        body_all = ('"response_type":', '"model":', '"time":',)
        ctype_any = ('application/json',)
        if (all(m in body for m in body_all)) and (any(m in content_type for m in ctype_any)):
            self.set_info(
                severity='high',
                reason='DATAGERRY - Improper Access Control detected',
                path=path,
            )
            return True
        return False

