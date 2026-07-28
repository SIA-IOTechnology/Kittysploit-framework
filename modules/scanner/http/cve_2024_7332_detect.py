#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""A critical vulnerability has been discovered in TOTOLINK CP450 version 4."""

from kittysploit import *
from lib.protocols.http.http_client import Http_client


class Module(Scanner, Http_client):
    __info__ = {
        'name': 'TOTOLINK CP450 v4.1.0cu.747_B20191224 - Hard-Coded Password Vulnerability Detection',
        'description': 'A critical vulnerability has been discovered in TOTOLINK CP450 version 4.1.0cu.747_B20191224. This vulnerability affects an unknown part of the file /web_cste/cgi-bin/product.ini of the Telnet Service component. The issue stems from the use of a hard-coded password, which can be exploited remotely without any user interaction.',
        'author': ['KittySploit Team'],
        'severity': 'critical',
        'tags': ['web', 'scanner', 'cve', 'cve2024', 'totolink', 'vuln'],
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
                'suggested_followups': ['auxiliary/scanner/http/login_page_detector'],
            },
        },
        'references': [
            'https://github.com/abcdefg-png/IoT-vulnerable/blob/main/TOTOLINK/CP450/product.md',
            'https://nvd.nist.gov/vuln/detail/CVE-2024-7332',
            'https://cvefeed.io/vuln/detail/CVE-2024-7332',
            'https://www.tenable.com/cve/CVE-2024-7332',
        ],
        'cve': 'CVE-2024-7332',
    }

    def run(self):
        r = self.http_request(method="GET", path='/web_cste/cgi-bin/product.ini', allow_redirects=False)
        if not r or r.status_code != 200:
            return False
        body = r.text or ""
        body_all = ('[PRODUCT]', '[WLAN]', 'HostName',)
        if (all(m in body for m in body_all)):
            self.set_info(
                severity='critical',
                reason="TOTOLINK CP450 v4.1.0cu.747_B20191224 - Hard-Coded Password Vulnerability detected",
                path='/web_cste/cgi-bin/product.ini',
            )
            return True
        return False

