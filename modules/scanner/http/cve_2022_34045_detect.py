#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""WAVLINK WN530HG4 M30HG4."""

from kittysploit import *
from lib.protocols.http.http_client import Http_client


class Module(Scanner, Http_client):
    __info__ = {
        'name': 'WAVLINK WN530HG4 - Improper Access Control Detection',
        'description': 'WAVLINK WN530HG4 M30HG4.V5030.191116 is susceptible to improper access control. It contains a hardcoded encryption/decryption key for its configuration files at /etc_ro/lighttpd/www/cgi-bin/ExportAllSettings.sh. An attacker can possibly obtain sensitive information, modify data, and/or execute unauthorized operations.',
        'author': ['KittySploit Team'],
        'severity': 'critical',
        'tags': ['web', 'scanner', 'cve', 'cve2022', 'wavlink', 'exposure', 'vuln'],
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
            'https://drive.google.com/file/d/1s5uZGC_iSzfCJt9BJ8h-P24vmsrmttrf/view?usp=sharing',
            'https://nvd.nist.gov/vuln/detail/CVE-2022-34045',
            'https://github.com/ARPSyndicate/kenzer-templates',
            'https://github.com/ARPSyndicate/cvemon',
        ],
        'cve': 'CVE-2022-34045',
    }

    def run(self):
        path = '/backupsettings.dat'
        r = self.http_request(method='GET', path=path, allow_redirects=False)
        if not r or r.status_code != 200:
            return False
        body = r.text or ""
        headers = "\n".join(f"{k}: {v}" for k, v in r.headers.items())
        body_any = ('Salted__',)
        header_any = ('application/octet-stream',)
        if (any(m in body for m in body_any)) and (any(m in headers for m in header_any)):
            self.set_info(severity='critical', reason='WAVLINK WN530HG4 - Improper Access Control detected', path=path)
            return True
        return False

