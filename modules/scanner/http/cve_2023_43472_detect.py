#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""An issue in MLFlow versions 2."""

from kittysploit import *
from lib.protocols.http.http_client import Http_client


class Module(Scanner, Http_client):
    __info__ = {
        'name': 'MLFlow < 2.8.1 - Sensitive Information Disclosure Detection',
        'description': 'An issue in MLFlow versions 2.8.1 and before allows a remote attacker to obtain sensitive information via a crafted request to REST API.',
        'author': ['KittySploit Team'],
        'severity': 'high',
        'tags': ['web', 'scanner', 'cve', 'cve2023', 'mflow', 'exposure', 'vuln'],
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
            'https://www.contrastsecurity.com/security-influencers/discovering-mlflow-framework-zero-day-vulnerability-machine-language-model-security-contrast-security',
            'https://nvd.nist.gov/vuln/detail/CVE-2023-43472',
        ],
        'cve': 'CVE-2023-43472',
    }

    def run(self):
        r = self.http_request(method="GET", path='/api/2.0/preview/mlflow/experiments/list', allow_redirects=False)
        if not r or r.status_code != 200:
            return False
        body = r.text or ""
        headers = "\n".join(f"{k}: {v}" for k, v in r.headers.items())
        body_all = ('experiment_id\\', ':', 'lifecycle_stage\\')
        header_any = ('application/json',)
        if (all(m in body for m in body_all)) and (any(m in headers for m in header_any)):
            self.set_info(
                severity='high',
                reason="MLFlow < 2.8.1 - Sensitive Information Disclosure detected",
                path='/api/2.0/preview/mlflow/experiments/list',
            )
            return True
        return False

