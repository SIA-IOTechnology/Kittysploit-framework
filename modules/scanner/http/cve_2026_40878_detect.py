#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""mailcow < 2026-03b reflects raw REQUEST_URI into JavaScript and href links on the login page, allowing attacke."""

from kittysploit import *
from lib.protocols.http.http_client import Http_client


class Module(Scanner, Http_client):
    __info__ = {
        'name': 'Mailcow < 2026-03b - Href Link Injection Detection',
        'description': 'mailcow < 2026-03b reflects raw REQUEST_URI into JavaScript and href links on the login page, allowing attackers to inject parameters that break JS logic and enable phishing.',
        'author': ['KittySploit Team'],
        'severity': 'low',
        'tags': ['web', 'scanner', 'cve', 'cve2026', 'mailcow', 'link-injection'],
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
            'https://github.com/mailcow/mailcow-dockerized/security/advisories/GHSA-xv9r-j862-5hqf',
            'https://github.com/mailcow/mailcow-dockerized',
            'https://nvd.nist.gov/vuln/detail/CVE-2026-40878',
        ],
        'cve': 'CVE-2026-40878',
    }

    def run(self):
        r = self.http_request(method="GET", path='/?session_expired=true&redirect=http://evil.com', allow_redirects=False)
        if not r or r.status_code != 200:
            return False
        body = r.text or ""
        body_all = ('function setLang', "$.post( '/?session_expired=true&amp;redirect=http://evil.com",)
        if (all(m in body for m in body_all)):
            self.set_info(
                severity='low',
                reason="Mailcow < 2026-03b - Href Link Injection detected",
                path='/?session_expired=true&redirect=http://evil.com',
            )
            return True
        return False

