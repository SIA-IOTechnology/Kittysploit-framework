#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""A flaw was found in keycloak in versions prior to 13."""

import re
from kittysploit import *
from lib.protocols.http.http_client import Http_client


class Module(Scanner, Http_client):
    __info__ = {
        'name': 'KeyCloak - Information Exposure Detection',
        'description': 'A flaw was found in keycloak in versions prior to 13.0.0. The client registration endpoint allows fetching information about PUBLIC clients (like client secret) without authentication which could be an issue if the same PUBLIC client changed to CONFIDENTIAL later. The highest threat from this vulnerability is to data confidentiality.',
        'author': ['KittySploit Team'],
        'severity': 'medium',
        'tags': ['web', 'scanner', 'cve', 'cve2020', 'keycloak', 'exposure', 'redhat', 'vuln'],
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
            'https://bugzilla.redhat.com/show_bug.cgi?id=1906797',
            'https://nvd.nist.gov/vuln/detail/CVE-2020-27838',
            'https://github.com/muneebaashiq/MBProjects',
            'https://github.com/j4k0m/godkiller',
        ],
        'cve': 'CVE-2020-27838',
    }

    def run(self):
        r = self.http_request(method="GET", path='/auth/realms/master/clients-registrations/default/security-admin-console', allow_redirects=False)
        if not r or r.status_code != 200:
            return False
        body = r.text or ""
        headers = "\n".join(f"{k}: {v}" for k, v in r.headers.items())
        header_any = ('application/json',)
        body_regexes = ('"clientId":\\s*"security-admin-console"', '"secret":',)
        if (any(m in headers for m in header_any)) and (any(re.search(rx, body, 0) for rx in body_regexes)):
            self.set_info(
                severity='medium',
                reason="KeyCloak - Information Exposure detected",
                path='/auth/realms/master/clients-registrations/default/security-admin-console',
            )
            return True
        return False

