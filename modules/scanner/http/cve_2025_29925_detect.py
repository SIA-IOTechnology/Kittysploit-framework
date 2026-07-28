#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""A vulnerability in XWiki's REST API allows unauthenticated users to access information about private pages thr."""

from kittysploit import *
from lib.protocols.http.http_client import Http_client


class Module(Scanner, Http_client):
    __info__ = {
        'name': 'XWiki REST API - Private Pages Disclosure Detection',
        'description': "A vulnerability in XWiki's REST API allows unauthenticated users to access information about private pages through the pages endpoint. This could lead to disclosure of sensitive information and page metadata.",
        'author': ['KittySploit Team'],
        'severity': 'high',
        'tags': ['web', 'scanner', 'cve', 'cve2025', 'xwiki', 'rest-api', 'exposure', 'vkev', 'vuln'],
        'agent': {
            'risk': 'active',
            'effects': ['network_probe'],
            'expected_requests': 2,
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
        'cve': 'CVE-2025-29925',
    }

    def run(self):
        for path in ('/rest/wikis/xwiki/pages?space=', '/xwiki/rest/wikis/xwiki/pages?space='):
            r = self.http_request(method="GET", path=path, allow_redirects=False)
            if not r or r.status_code != 200:
                continue
            body = r.text or ""
            headers = "\n".join(f"{k}: {v}" for k, v in r.headers.items())
            body_all = ('<pageSummary', '<pages', '<xwikiRelativeUr',)
            header_any = ('text/xml', 'text/javascript',)
            if (all(m in body for m in body_all)) and (any(m in headers for m in header_any)):
                self.set_info(
                    severity='high',
                    reason="XWiki REST API - Private Pages Disclosure detected",
                    path=path,
                )
                return True
        return False

