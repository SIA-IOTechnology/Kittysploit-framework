#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""The Kubernetes API server is vulnerable to a denial of service attack via YAML/JSON parsing."""

from kittysploit import *
from lib.protocols.http.http_client import Http_client


class Module(Scanner, Http_client):
    __info__ = {
        'name': 'Kubernetes API Server - YAML Parsing DoS (Billion Laughs) Detection',
        'description': 'The Kubernetes API server is vulnerable to a denial of service attack via YAML/JSON parsing. An attacker can send a specially crafted YAML/JSON payload that causes exponential memory consumption (Billion Laughs attack), leading to API server crash.',
        'author': ['KittySploit Team'],
        'severity': 'high',
        'tags': ['web', 'scanner', 'cve', 'cve2019', 'kubernetes', 'yaml', 'k8s'],
        'agent': {
            'risk': 'active',
            'effects': ['network_probe'],
            'expected_requests': 1,
            'reversible': True,
            'approval_required': False,
            'produces': ['tech_hints', 'risk_signals', 'endpoints'],
            'cost': 1.0,
            'noise': 0.4,
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
                        'capability': 'risk_signal',
                        'from_detail': '',
                    },
                ],
                'consumes_capabilities': [],
                'option_bindings': {},
                'suggested_followups': [],
            },
        },
        'references': [
            'https://gist.github.com/bgeesaman/0e0349e94cd22c48bf14d8a9b7d6b8f2',
            'https://github.com/kubernetes/kubernetes/issues/83253',
            'https://nvd.nist.gov/vuln/detail/CVE-2019-11253',
        ],
        'cve': 'CVE-2019-11253',
    }

    def run(self):
        path = '/apis/authorization.k8s.io/v1/selfsubjectaccessreviews'
        r = self.http_request(method='POST', path=path, allow_redirects=False, headers={'Content-Type': 'application/yaml'}, data='')
        if not r or r.status_code != 200:
            return False
        body = r.text or ""
        body_all = ('Invalid value', 'FieldValueInvalid', '422',)
        if all(m in body for m in body_all):
            self.set_info(severity='high', reason='Kubernetes API Server - YAML Parsing DoS (Billion Laughs) detected', path=path)
            return True
        return False

