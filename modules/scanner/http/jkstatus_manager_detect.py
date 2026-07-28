#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Exposed JKStatus manager which is a web-based tool that allows administrators to monitor and manage the connec."""

from kittysploit import *
from lib.protocols.http.http_client import Http_client


class Module(Scanner, Http_client):
    __info__ = {
        'name': 'JK Status Manager - Detect',
        'description': 'Exposed JKStatus manager which is a web-based tool that allows administrators to monitor and manage the connections between the Apache HTTP Server and the Tomcat application server.',
        'author': ['KittySploit Team'],
        'severity': 'low',
        'tags': ['web', 'scanner', 'exposure', 'config', 'jk', 'status', 'vuln'],
        'agent': {
            'risk': 'active',
            'effects': ['network_probe'],
            'expected_requests': 6,
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
            'https://github.com/PortSwigger/j2ee-scan/blob/master/src/main/java/burp/j2ee/issues/impl/JKStatus.java',
        ],
    }

    def run(self):
        for path in ('/', '/status', '/jkstatus', '/jkstatus-auth', '/jk-status', '/jkmanager', '/jkmanager-auth', '/jdkstatus'):
            r = self.http_request(method="GET", path=path, allow_redirects=False)
            if not r or r.status_code != 200:
                continue
            body = r.text or ""
            body_any = ('JK Status Manager',)
            if (any(m in body for m in body_any)):
                self.set_info(
                    severity='low',
                    reason="JK Status Manager detected",
                    path=path,
                )
                return True
        return False

