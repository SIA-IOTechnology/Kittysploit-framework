#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Detected AWS Elastic Beanstalk Dockerrun."""

from kittysploit import *
from lib.protocols.http.http_client import Http_client


class Module(Scanner, Http_client):
    __info__ = {
        'name': 'AWS Elastic Beanstalk Dockerrun.aws.json - Exposure Detection',
        'description': 'Detected AWS Elastic Beanstalk Dockerrun.aws.json configuration file was publicly accessible, potentially revealing Docker container definitions, image names, hostnames, port mappings, and infrastructure details.',
        'author': ['KittySploit Team'],
        'severity': 'medium',
        'tags': ['web', 'scanner', 'exposure', 'aws', 'docker', 'config', 'misconfig'],
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
        'references': ['https://docs.aws.amazon.com/elasticbeanstalk/latest/dg/create_deploy_docker_v2config.html'],
    }

    def run(self):
        for path in ('/Dockerrun.aws.json', '/static/Dockerrun.aws.json'):
            r = self.http_request(method="GET", path=path, allow_redirects=False)
            if not r or r.status_code != 200:
                continue
            body = r.text or ""
            body_any = ('application/json', 'text/plain',)
            body_all = ('AWSEBDockerrunVersion', 'containerDefinitions', 'image',)
            if (any(m in body for m in body_any)) and (all(m in body for m in body_all)):
                self.set_info(
                    severity='medium',
                    reason="AWS Elastic Beanstalk Dockerrun.aws.json - Exposure detected",
                    path=path,
                )
                return True
        return False

