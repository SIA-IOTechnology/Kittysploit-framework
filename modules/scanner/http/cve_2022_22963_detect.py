#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Spring Cloud Function routing-expression injection indicator (CVE-2022-22963)."""

from kittysploit import *
from lib.protocols.http.http_client import Http_client


class Module(Scanner, Http_client):
    __info__ = {
        'name': 'Spring Cloud Function - routing-expression Detection (CVE-2022-22963)',
        'description': (
            'Probes Spring Cloud Function endpoints for acceptance of the '
            'spring.cloud.function.routing-expression header (CVE-2022-22963). '
            'Uses a non-destructive SpEL expression; confirmation of RCE requires the '
            'companion exploit with a reverse payload.'
        ),
        'author': ['KittySploit Team'],
        'severity': 'high',
        'tags': [
            'web', 'scanner', 'cve', 'cve2022', 'spring', 'function', 'rce',
            'spel', 'unauth', 'kev', 'vuln',
        ],
        'agent': {
            'risk': 'active',
            'effects': ['network_probe'],
            'expected_requests': 2,
            'reversible': True,
            'approval_required': False,
            'produces': ['tech_hints', 'risk_signals', 'endpoints'],
            'cost': 1.0,
            'noise': 0.4,
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
                'produces_capabilities': [{'capability': 'risk_signal', 'from_detail': ''}],
                'consumes_capabilities': [],
                'option_bindings': {},
                'suggested_followups': [
                    'exploits/multi/http/spring_cloud_function_cve_2022_22963_rce',
                ],
            },
        },
        'references': [
            'https://tanzu.vmware.com/security/cve-2022-22963',
            'https://nvd.nist.gov/vuln/detail/CVE-2022-22963',
        ],
        'cve': 'CVE-2022-22963',
    }

    path = OptString('/functionRouter', 'Function endpoint path', required=False)

    def run(self):
        path = str(self.path or '/functionRouter')
        if not path.startswith('/'):
            path = '/' + path
        # Harmless SpEL that should not crash a vulnerable routing parser the same way
        # as a missing header on some builds; look for 500 vs baseline differences.
        baseline = self.http_request(
            method='POST',
            path=path,
            data='kittysploit',
            headers={'Content-Type': 'text/plain'},
            allow_redirects=False,
        )
        probe = self.http_request(
            method='POST',
            path=path,
            data='kittysploit',
            headers={
                'Content-Type': 'text/plain',
                'spring.cloud.function.routing-expression': 'T(java.lang.Math).random()',
            },
            allow_redirects=False,
        )
        if not probe:
            return False
        # Vulnerable apps often return 500 when SpEL exec is attempted / routed.
        body = (probe.text or '').lower()
        if probe.status_code == 500 and (
            'spel' in body
            or 'routing-expression' in body
            or 'function' in body
            or (baseline is not None and baseline.status_code != 500)
        ):
            self.set_info(
                severity='high',
                reason='Spring Cloud Function accepts routing-expression header (CVE-2022-22963 indicator)',
                path=path,
            )
            return True
        # Some builds return 200 with empty body after evaluating expression.
        if probe.status_code in (200, 500) and 'spring' in ((probe.headers.get('X-Application-Context') or '') + body):
            self.set_info(
                severity='medium',
                reason='Possible Spring Cloud Function routing-expression handling',
                path=path,
            )
            return True
        return False
