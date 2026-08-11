#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Searches for exposed Kubernetes API servers which return version information unauthenticated."""

from kittysploit import *
from lib.protocols.http.http_client import Http_client
from lib.scanner.http.probe_guard import validate_json_probe
from lib.scanner.http.response_validation import looks_like_kubernetes_version


class Module(Scanner, Http_client):
    __info__ = {
        'name': 'Kubernetes Version Exposure Detection',
        'description': 'Searches for exposed Kubernetes API servers which return version information unauthenticated. For Google Kubernetes Engine (GKE) and Amazon Elastic Kubernetes Service (EKS) this template will extract default patch version for you.',
        'author': ['KittySploit Team'],
        'severity': 'info',
        'tags': ['web', 'scanner', 'technology', 'tech', 'k8s', 'kubernetes', 'devops'],
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
            'https://cloud.google.com/kubernetes-engine/docs/release-notes',
            'https://docs.aws.amazon.com/eks/latest/userguide/kubernetes-versions.html',
        ],
    }

    def run(self):
        data, _response = validate_json_probe(
            self.http_request,
            "/version",
            looks_like_kubernetes_version,
        )
        if not data:
            return False
        self.set_info(
            severity='info',
            reason="Kubernetes Version Exposure detected",
            path='/version',
        )
        return True

