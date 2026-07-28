#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Detects Adobe AEM Debugging Client Libraries."""

from kittysploit import *
from lib.protocols.http.http_client import Http_client


class Module(Scanner, Http_client):
    __info__ = {
        'name': 'Adobe AEM Debugging Client Libraries Detection',
        'description': 'Detects Adobe AEM Debugging Client Libraries.',
        'author': ['KittySploit Team'],
        'severity': 'info',
        'tags': ['web', 'scanner', 'misconfiguration', 'misconfig', 'aem', 'adobe', 'vuln'],
        'agent': {
            'risk': 'active',
            'effects': ['network_probe'],
            'expected_requests': 5,
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
            'https://aem4beginner.blogspot.com/debugging-client-libraries',
            'https://adobe-consulting-services.github.io/acs-aem-tools/features/dumplibs/index.html',
        ],
    }

    def run(self):
        for path in ('/libs/cq/ui/content/dumplibs.html', '/libs/granite/ui/content/dumplibs.validate.html', '/libs/granite/ui/content/dumplibs.rebuild.html', '/libs/granite/ui/content/dumplibs.test.html', '/libs/granite/ui/content/dumplibs.html'):
            r = self.http_request(method="GET", path=path, allow_redirects=False)
            if not r or r.status_code != 200:
                continue
            body = r.text or ""
            body_any = ('<title>Client Libraries</title>', '<title>Rebuild Client Libraries</title>', '<title>Client Libraries Test Output</title>',)
            if (any(m in body for m in body_any)):
                self.set_info(
                    severity='info',
                    reason="Adobe AEM Debugging Client Libraries detected",
                    path=path,
                )
                return True
        return False

