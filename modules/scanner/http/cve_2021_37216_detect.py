#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""QSAN Storage Manager before 3."""

from kittysploit import *
from lib.protocols.http.http_client import Http_client


class Module(Scanner, Http_client):
    __info__ = {
        'name': 'QSAN Storage Manager <3.3.3 - Cross-Site Scripting Detection',
        'description': 'QSAN Storage Manager before 3.3.3 contains a reflected cross-site scripting vulnerability. Header page parameters do not filter special characters. Remote attackers can inject JavaScript to access and modify specific data.',
        'author': ['KittySploit Team'],
        'severity': 'medium',
        'tags': ['web', 'scanner', 'cve', 'cve2021', 'xss', 'qsan', 'storage', 'vuln'],
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
            'https://www.twcert.org.tw/tw/cp-132-4962-44cd2-1.html',
            'https://nvd.nist.gov/vuln/detail/CVE-2021-37216',
            'https://github.com/ARPSyndicate/kenzer-templates',
            'https://github.com/ARPSyndicate/cvemon',
        ],
        'cve': 'CVE-2021-37216',
    }

    def run(self):
        r = self.http_request(method="GET", path='/http_header.php', allow_redirects=False)
        if not r or r.status_code != 200:
            return False
        body = (r.text or "").lower()
        headers = "\n".join(f"{k}: {v}" for k, v in r.headers.items()).lower()
        body_any = ('"http_x_trigger_xss":"<script>alert(1)</script>"',)
        header_any = ('x-xss-protection', 'text/html',)
        if (any(m in body for m in body_any)) and (any(m in headers for m in header_any)):
            self.set_info(
                severity='medium',
                reason="QSAN Storage Manager <3.3.3 - Cross-Site Scripting detected",
                path='/http_header.php',
            )
            return True
        return False

