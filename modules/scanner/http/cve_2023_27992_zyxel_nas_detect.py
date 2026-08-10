#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Zyxel NAS authentication bypass indicator for Jun/Nov 2023 vulns (CVE-2023-27992 family)."""

import re
from kittysploit import *
from lib.protocols.http.http_client import Http_client


class Module(Scanner, Http_client):
    __info__ = {
        'name': 'Zyxel NAS - Auth Bypass Indicator (CVE-2023-27992 family)',
        'description': (
            'Detects Zyxel NAS authentication bypass via '
            '/cmd,/ck6fup6/zylog_main/configure_mail_syslog, indicating exposure to the '
            'Jun/Nov 2023 vulnerability set including pre-auth command injection '
            'CVE-2023-27992 and related issues.'
        ),
        'author': ['KittySploit Team'],
        'severity': 'critical',
        'tags': [
            'web', 'scanner', 'cve', 'cve2023', 'zyxel', 'nas', 'auth-bypass',
            'rce', 'unauth', 'kev', 'vuln',
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
                'produces_capabilities': [{'capability': 'admin_surface', 'from_detail': ''}],
                'consumes_capabilities': [],
                'option_bindings': {},
                'suggested_followups': ['scanner/http/cve_2020_9054_detect'],
            },
        },
        'references': [
            'https://www.zyxel.com/global/en/support/security-advisories/zyxel-security-advisory-for-pre-authentication-command-injection-vulnerability-in-nas-products',
            'https://www.ibm.com/think/x-force/ibm-identifies-zero-day-vulnerability-zyxel-nas-devices',
            'https://nvd.nist.gov/vuln/detail/CVE-2023-27992',
        ],
        'cve': 'CVE-2023-27992',
    }

    def run(self):
        probe = '/cmd,/ck6fup6/zylog_main/configure_mail_syslog'
        r1 = self.http_request(method='GET', path=probe, allow_redirects=False)
        if not r1 or r1.status_code != 302:
            return False

        path = '/cmd,/ck6fup6/zylog_main/configure_mail_syslog/favicon.ico'
        r2 = self.http_request(method='GET', path=path, allow_redirects=False)
        if not r2 or r2.status_code != 200:
            return False
        body = r2.text or ''
        if re.search(r'\{\s*"errorMsg"\s*:\s*"OK"\s*\}', body):
            self.set_info(
                severity='critical',
                reason='Zyxel NAS auth bypass indicator (CVE-2023-27992 family)',
                path=path,
            )
            return True
        return False
