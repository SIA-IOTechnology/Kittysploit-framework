#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Oracle GlassFish Admin Console TRACE auth bypass (CVE-2011-1511)."""

from kittysploit import *
from lib.protocols.http.http_client import Http_client


class Module(Scanner, Http_client):
    __info__ = {
        'name': 'GlassFish - Admin Console TRACE Bypass Detection (CVE-2011-1511)',
        'description': (
            'Detects CVE-2011-1511 by issuing TRACE to manageUserNew.jsf and matching '
            'ConfirmPassword / NewPassword form fields.'
        ),
        'author': ['KittySploit Team'],
        'severity': 'critical',
        'tags': [
            'web', 'scanner', 'cve', 'cve2011', 'glassfish', 'oracle', 'auth-bypass', 'unauth', 'vuln',
        ],
        'agent': {
            'risk': 'active',
            'effects': ['network_probe'],
            'expected_requests': 1,
            'reversible': True,
            'approval_required': False,
            'produces': ['tech_hints', 'risk_signals', 'endpoints'],
            'cost': 1.0,
            'noise': 0.3,
            'value': 0.9,
            'requires': {
                'min_endpoints': 0, 'min_params': 0,
                'tech_hints_any': [], 'tech_hints_all': [],
                'specializations_any': [], 'risk_signals_any': [],
                'auth_session': False, 'capabilities_any': [], 'capabilities_all': [],
                'confidence_min': {}, 'confidence_min_any': {},
                'endpoint_pattern_any': [], 'param_any': [], 'api_surface_ready': False,
            },
            'chain': {
                'produces_capabilities': [{'capability': 'admin_surface', 'from_detail': ''}],
                'consumes_capabilities': [],
                'option_bindings': {},
                'suggested_followups': [],
            },
        },
        'references': [
            'https://nvd.nist.gov/vuln/detail/CVE-2011-1511',
        ],
        'cve': 'CVE-2011-1511',
    }

    port = OptPort(4848, 'GlassFish admin console port', True)

    def run(self):
        path = (
            '/common/security/realms/manageUserNew.jsf'
            '?name=admin-realm&configName=server-config&bare=true'
        )
        r = self.http_request(method='TRACE', path=path, allow_redirects=False)
        if not r:
            return False
        body = r.text or ''
        if '405 TRACE method is not allowed' in body:
            return False
        if 'ConfirmPassword' in body and 'newPasswordProp:NewPassword' in body:
            self.set_info(
                severity='critical',
                reason='GlassFish Admin Console TRACE bypass (CVE-2011-1511)',
                path=path.split('?')[0],
            )
            return True
        return False
