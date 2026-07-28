#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Seagate NAS OS version 4."""

from kittysploit import *
from lib.protocols.http.http_client import Http_client


class Module(Scanner, Http_client):
    __info__ = {
        'name': 'Seagate NAS OS 4.3.15.1 - Server Information Disclosure Detection',
        'description': 'Seagate NAS OS version 4.3.15.1 has insufficient access control which allows attackers to obtain information about the NAS without authentication via empty POST requests in /api/external/7.0/system.System.get_infos.',
        'author': ['KittySploit Team'],
        'severity': 'high',
        'tags': ['web', 'scanner', 'cve', 'cve2018', 'seagate', 'nasos', 'disclosure', 'unauth', 'vkev', 'vuln'],
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
            'https://blog.securityevaluators.com/invading-your-personal-cloud-ise-labs-exploits-the-seagate-stcr3000101-ecf89de2170',
            'https://nvd.nist.gov/vuln/detail/CVE-2018-12296',
            'https://github.com/ARPSyndicate/kenzer-templates',
        ],
        'cve': 'CVE-2018-12296',
    }

    def run(self):
        path = '/api/external/7.0/system.System.get_infos'
        r = self.http_request(method='POST', path=path, allow_redirects=False, headers={'Referer': '{{BaseURL}}'}, data='')
        if not r or r.status_code != 200:
            return False
        body = r.text or ""
        body_all = ('"version":', '"serial_number":',)
        if all(m in body for m in body_all):
            self.set_info(severity='high', reason='Seagate NAS OS 4.3.15.1 - Server Information Disclosure detected', path=path)
            return True
        return False

