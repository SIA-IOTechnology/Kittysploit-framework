#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""QNAP QTS 5.0.1 / QuTS hero h5.0.1 SQLi exposure (CVE-2022-27596)."""

import re

from kittysploit import *
from lib.protocols.http.http_client import Http_client


def _qts_vulnerable(version: str) -> bool:
    v = str(version or '').strip().lower()
    if not v:
        return False
    # QTS 5.0.1 builds before 20221201 / QuTS hero h5.0.1 before 20221215
    m = re.search(r'(\d+)\.(\d+)\.(\d+)\.(\d+)', v)
    if not m:
        if v.startswith('5.0.1') or v.startswith('h5.0.1'):
            return True
        return False
    major, minor, patch, build = (int(m.group(i)) for i in range(1, 5))
    if major == 5 and minor == 0 and patch == 1:
        return build < 2234
    if v.startswith('h') and major == 5 and minor == 0 and patch == 1:
        return build < 2248
    return False


class Module(Scanner, Http_client):
    __info__ = {
        'name': 'QNAP QTS - CVE-2022-27596 Exposure Detection',
        'description': (
            'Detects QNAP NAS running vulnerable QTS 5.0.1 or QuTS hero h5.0.1 firmware '
            '(before patched builds for CVE-2022-27596 unauthenticated SQL injection). '
            'Version is parsed from authLogin.cgi when exposed.'
        ),
        'author': ['KittySploit Team'],
        'severity': 'critical',
        'tags': ['web', 'scanner', 'cve', 'cve2022', 'qnap', 'qts', 'nas', 'sqli', 'kev'],
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
                'suggested_followups': [
                    'scanner/http/qnap_qts_detect',
                    'exploits/linux/http/qnap_cve_2023_47218_rce',
                ],
            },
        },
        'references': [
            'https://www.qnap.com/en/security-advisory/qsa-23-01',
            'https://nvd.nist.gov/vuln/detail/CVE-2022-27596',
        ],
        'cve': 'CVE-2022-27596',
    }

    def _read_version(self) -> str:
        for path in (
            '/cgi-bin/authLogin.cgi',
            '/cgi-bin/login.cgi',
        ):
            r = self.http_request(method='GET', path=path, allow_redirects=False)
            if not r or r.status_code != 200:
                continue
            body = r.text or ''
            for pat in (
                r'<version>([^<]+)</version>',
                r'"version"\s*:\s*"([^"]+)"',
                r'QTS\s+([0-9h\.]+)',
            ):
                m = re.search(pat, body, re.I)
                if m:
                    return m.group(1).strip()
        return ''

    def run(self):
        ver = self._read_version()
        if not ver:
            r = self.http_request(method='GET', path='/', allow_redirects=False)
            body = (r.text or '') if r else ''
            if 'QNAP' not in body and 'qnap' not in body.lower():
                return False
            self.set_info(
                severity='high',
                reason='QNAP NAS detected; firmware version unknown — check CVE-2022-27596 manually',
                path='/',
            )
            return True
        if _qts_vulnerable(ver):
            self.set_info(
                severity='critical',
                reason=f'QNAP firmware {ver} in CVE-2022-27596 affected range',
                path='/cgi-bin/authLogin.cgi',
            )
            return True
        return False
