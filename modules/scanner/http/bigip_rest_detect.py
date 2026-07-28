#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""F5 BIG-IP iControl REST API discovered and may be vulnerable to an authentication bypass (not tested)."""

from kittysploit import *
from lib.protocols.http.http_client import Http_client


class Module(Scanner, Http_client):
    __info__ = {
        'name': 'F5 BIG-IP iControl REST Panel - Detect',
        'description': 'F5 BIG-IP iControl REST API discovered and may be vulnerable to an authentication bypass (not tested).',
        'author': ['KittySploit Team'],
        'severity': 'info',
        'tags': ['web', 'scanner', 'panel', 'bigip', 'f5'],
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
                'confidence_min': {
                },
                'confidence_min_any': {
                },
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
                'option_bindings': {
                },
                'suggested_followups': ['auxiliary/scanner/http/login_page_detector'],
            },
        },
        'references': [
            'https://nvd.nist.gov/vuln/detail/CVE-2022-1388',
            'https://support.f5.com/csp/article/K23605346',
            'https://clouddocs.f5.com/products/big-iq/mgmt-api/v5.4/ApiReferences/bigiq_api_ref/r_auth_login.html',
        ],
    }

    def run(self):
        r = self.http_request(method="GET", path='/mgmt/shared/authn/login', allow_redirects=False)
        if not r or r.status_code != 200:
            return False
        body = (r.text or "")
        markers = (
            'resterrorresponse',
        )
        if any(m in body for m in markers):
            self.set_info(
                severity='info',
                reason="F5 BIG-IP iControl REST Panel detected",
                path='/mgmt/shared/authn/login',
            )
            return True
        return False

