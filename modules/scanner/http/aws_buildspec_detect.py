#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Detected the presence of the AWS CodeBuild buildspec."""

from kittysploit import *
from lib.protocols.http.http_client import Http_client


class Module(Scanner, Http_client):
    __info__ = {
        'name': 'AWS CodeBuild Build Spec - Exposure Detection',
        'description': "Detected the presence of the AWS CodeBuild buildspec.yml file. This file contains build commands and settings that may disclose sensitive information about the application's build process and infrastructure.",
        'author': ['KittySploit Team'],
        'severity': 'low',
        'tags': ['web', 'scanner', 'exposure', 'aws', 'codebuild', 'config', 'devops'],
        'agent': {
            'risk': 'active',
            'effects': ['network_probe'],
            'expected_requests': 2,
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
        'references': ['https://docs.aws.amazon.com/codebuild/latest/userguide/build-spec-ref.html'],
    }

    def run(self):
        for path in ('/buildspec.yml', '/buildspec.yaml'):
            r = self.http_request(method="GET", path=path, allow_redirects=False)
            if not r or r.status_code != 200:
                continue
            body = r.text or ""
            headers = "\n".join(f"{k}: {v}" for k, v in r.headers.items())
            body_all = ('version:', 'phases:', 'build:', 'commands:',)
            header_any = ('text/yaml', 'text/plain', 'application/x-yaml',)
            if (all(m in body for m in body_all)) and (any(m in headers for m in header_any)):
                self.set_info(
                    severity='low',
                    reason="AWS CodeBuild Build Spec - Exposure detected",
                    path=path,
                )
                return True
        return False

