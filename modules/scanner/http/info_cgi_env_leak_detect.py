#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Detected exposure of server environment variables through the info."""

from kittysploit import *
from lib.protocols.http.http_client import Http_client


class Module(Scanner, Http_client):
    __info__ = {
        'name': 'info.cgi  Environment Variable - Disclosure Detection',
        'description': 'Detected exposure of server environment variables through the info.cgi script. This can leak sensitive paths, internal IPs, software versions, credentials in env, etc.',
        'author': ['KittySploit Team'],
        'severity': 'medium',
        'tags': ['web', 'scanner', 'misconfiguration', 'cgi', 'exposure', 'info', 'env', 'disclosure', 'generic'],
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
            'https://www.acunetix.com/vulnerabilities/web/test-cgi-script-leaking-environment-variables/',
            'https://book.hacktricks.xyz/network-services-pentesting/pentesting-web/cgi',
        ],
    }

    def run(self):
        for path in ('/info.cgi', '/cgi-bin/info.cgi', '/cgi-sys/info.cgi', '/scripts/info.cgi', '/lite-scripts/info.cgi'):
            r = self.http_request(method="GET", path=path, allow_redirects=False)
            if not r or r.status_code != 200:
                continue
            body = r.text or ""
            body_any = ('SERVER_SOFTWARE', 'SERVER_NAME', 'GATEWAY_INTERFACE', 'SERVER_PROTOCOL', 'REQUEST_METHOD', 'QUERY_STRING', 'REMOTE_ADDR', 'HTTP_USER_AGENT', 'PATH=', '/bin:', '/usr/bin:', 'LD_LIBRARY_PATH', 'MYSQL_HOME', 'OPENSSL_CONF', 'DOCUMENT_ROOT', 'SCRIPT_FILENAME',)
            if (any(m in body for m in body_any)):
                self.set_info(
                    severity='medium',
                    reason="info.cgi  Environment Variable - Disclosure detected",
                    path=path,
                )
                return True
        return False

