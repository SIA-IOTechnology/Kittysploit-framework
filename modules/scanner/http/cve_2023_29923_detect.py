#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""PowerJob V4."""

from kittysploit import *
from lib.protocols.http.http_client import Http_client


class Module(Scanner, Http_client):
    __info__ = {
        'name': 'PowerJob <=4.3.2 - Unauthenticated Access Detection',
        'description': 'PowerJob V4.3.1 is vulnerable to Insecure Permissions. via the list job interface.',
        'author': ['KittySploit Team'],
        'severity': 'medium',
        'tags': ['web', 'scanner', 'cve2023', 'cve', 'powerjob', 'unauth', 'vuln'],
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
            'https://github.com/PowerJob/PowerJob/issues/587',
            'https://nvd.nist.gov/vuln/detail/CVE-2023-29923',
            'https://github.com/KayCHENvip/vulnerability-poc',
            'https://github.com/Le1a/CVE-2023-29923',
            'https://github.com/Threekiii/Awesome-POC',
        ],
        'cve': 'CVE-2023-29923',
    }

    def run(self):
        path = '/job/list'
        r = self.http_request(method='POST', path=path, allow_redirects=False, headers={'Content-Type': 'application/json;charset=UTF-8'}, data='{"appId":1,"index":0,"pageSize":10}\n')
        if not r or r.status_code != 200:
            return False
        body = r.text or ""
        headers = "\n".join(f"{k}: {v}" for k, v in r.headers.items())
        body_any = ('{"success":true,"data":{"index":0,"pageSize":10,',)
        header_any = ('application/json',)
        if (any(m in body for m in body_any)) and (any(m in headers for m in header_any)):
            self.set_info(severity='medium', reason='PowerJob <=4.3.2 - Unauthenticated Access detected', path=path)
            return True
        return False

