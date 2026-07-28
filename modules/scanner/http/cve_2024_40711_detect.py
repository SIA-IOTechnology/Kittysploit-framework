#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""A deserialization of untrusted data vulnerability with a malicious payload can allow an unauthenticated remote."""

from kittysploit import *
from lib.protocols.http.http_client import Http_client


class Module(Scanner, Http_client):
    __info__ = {
        'name': 'Veeam Backup & Replication - Unauthenticated Detection',
        'description': 'A deserialization of untrusted data vulnerability with a malicious payload can allow an unauthenticated remote code execution (RCE).',
        'author': ['KittySploit Team'],
        'severity': 'critical',
        'tags': ['web', 'scanner', 'cve', 'cve2024', 'veeam', 'backup', 'unauth', 'passive', 'kev', 'vkev', 'vuln'],
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
            'https://x.com/codewhitesec/status/1831720125747069389?s=46',
            'https://www.veeam.com/kb4649',
            'https://nvd.nist.gov/vuln/detail/CVE-2024-40711',
        ],
        'cve': 'CVE-2024-40711',
    }

    def run(self):
        path = '/api/v1/serverinfo'
        r = self.http_request(method='GET', path=path, allow_redirects=False, headers={'X-Api-Version': '1.1-rev1'})
        if not r or r.status_code != 200:
            return False
        body = r.text or ""
        content_type = r.headers.get("Content-Type") or r.headers.get("content-type") or ""
        body_all = ('"databaseVendor":', '"databaseContentVersion":',)
        ctype_any = ('application/json',)
        if (all(m in body for m in body_all)) and (any(m in content_type for m in ctype_any)):
            self.set_info(
                severity='critical',
                reason='Veeam Backup & Replication - Unauthenticated detected',
                path=path,
            )
            return True
        return False

