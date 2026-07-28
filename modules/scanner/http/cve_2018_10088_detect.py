#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Buffer overflow in XiongMai uc-httpd 1."""

from kittysploit import *
from lib.protocols.http.http_client import Http_client


class Module(Scanner, Http_client):
    __info__ = {
        'name': 'XiongMai uc-httpd 1.0.0 - Buffer Overflow Detection',
        'description': 'Buffer overflow in XiongMai uc-httpd 1.0.0 has unspecified impact and attack vectors, a different vulnerability than CVE-2017-16725.',
        'author': ['KittySploit Team'],
        'severity': 'critical',
        'tags': ['web', 'scanner', 'cve', 'cve2018', 'xiongmai', 'buffer-overflow', 'rce', 'passive', 'vkev', 'vuln'],
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
            'https://nvd.nist.gov/vuln/detail/CVE-2018-10088',
            'https://www.exploit-db.com/exploits/44864',
            'https://github.com/bitfu/uc-httpd-1.0.0-buffer-overflow-exploit',
            'https://github.com/KostasEreksonas/Besder-6024PB-XMA501-ip-camera-security-investigation',
        ],
        'cve': 'CVE-2018-10088',
    }

    def run(self):
        path = '/'
        r = self.http_request(method='GET', path=path, allow_redirects=False)
        if not r or r.status_code != 200:
            return False
        headers = "\n".join(f"{k}: {v}" for k, v in r.headers.items()).lower()
        header_any = ('uc-httpd',)
        if any(m in headers for m in header_any):
            self.set_info(
                severity='critical',
                reason='XiongMai uc-httpd 1.0.0 - Buffer Overflow detected',
                path=path,
            )
            return True
        return False

