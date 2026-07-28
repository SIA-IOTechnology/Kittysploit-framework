#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""LocalStack (localstack."""

from kittysploit import *
from lib.protocols.http.http_client import Http_client


class Module(Scanner, Http_client):
    __info__ = {
        'name': 'LocalStack - Detect',
        'description': 'LocalStack (localstack.cloud / github.com/localstack/localstack) is a local AWS cloud-service emulator widely used in development and CI. It typically listens on TCP 4566 and exposes an unauthenticated /_localstack/health endpoint that lists every emulated service and its enabled state. An exposed LocalStack on a non-loopback interface gives an attacker a fully-functional fake AWS account, including S3, SQS, IAM, SecretsManager and Lambda execution.',
        'author': ['KittySploit Team'],
        'severity': 'info',
        'tags': ['web', 'scanner', 'technology', 'localstack', 'aws', 'cloud', 'tech'],
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
                'suggested_followups': [],
            },
        },
        'references': [
            'https://github.com/localstack/localstack',
            'https://docs.localstack.cloud/references/internal-endpoints/',
        ],
    }

    def run(self):
        path = '/_localstack/health'
        r = self.http_request(method='GET', path=path, allow_redirects=False)
        if not r or r.status_code != 200:
            return False
        headers = "\n".join(f"{k}: {v}" for k, v in r.headers.items()).lower()
        header_any = ('application/json',)
        if any(m in headers for m in header_any):
            self.set_info(
                severity='info',
                reason='LocalStack detected',
                path=path,
            )
            return True
        return False

