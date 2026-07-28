#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""LoginStatusServlet is exposed, it allows to bruteforce credentials."""

from kittysploit import *
from lib.protocols.http.http_client import Http_client


class Module(Scanner, Http_client):
    __info__ = {
        'name': 'AEM Login Status Detection',
        'description': 'LoginStatusServlet is exposed, it allows to bruteforce credentials.',
        'author': ['KittySploit Team'],
        'severity': 'info',
        'tags': ['web', 'scanner', 'misconfiguration', 'aem', 'adobe', 'misconfig', 'vuln'],
        'agent': {
            'risk': 'active',
            'effects': ['network_probe'],
            'expected_requests': 3,
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
            'https://www.slideshare.net/0ang3el/hunting-for-security-bugs-in-aem-webapps-129262212',
            'https://github.com/thomashartm/burp-aem-scanner/blob/master/src/main/java/burp/actions/dispatcher/LoginStatusServletExposed.java',
        ],
    }

    def run(self):
        for path in ('/system/sling/loginstatus', '/system/sling/loginstatus.css', '///system///sling///loginstatus'):
            r = self.http_request(method="GET", path=path, allow_redirects=False)
            if not r or r.status_code != 200:
                continue
            body = r.text or ""
            body_any = ('CREDENTIAL_CHALLENGE',)
            if (any(m in body for m in body_any)):
                self.set_info(
                    severity='info',
                    reason="AEM Login Status detected",
                    path=path,
                )
                return True
        return False

