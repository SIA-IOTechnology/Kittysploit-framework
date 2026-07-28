#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""A Kubernetes Pods API was discovered."""

from kittysploit import *
from lib.protocols.http.http_client import Http_client


class Module(Scanner, Http_client):
    __info__ = {
        'name': 'Kubernetes Pods - API Discovery & Remote Code Execution Detection',
        'description': 'A Kubernetes Pods API was discovered. When the service port is available, unauthenticated users can execute commands inside the container.',
        'author': ['KittySploit Team'],
        'severity': 'critical',
        'tags': ['web', 'scanner', 'misconfiguration', 'k8', 'unauth', 'kubernetes', 'devops', 'misconfig', 'vuln'],
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
        'references': [
            'https://github.com/officialhocc/Kubernetes-Kubelet-RCE',
            'https://blog.binaryedge.io/2018/12/06/kubernetes-being-hijacked-worldwide/',
        ],
    }

    def run(self):
        for path in ('/pods', '/api/v1/pods'):
            r = self.http_request(method="GET", path=path, allow_redirects=False)
            if not r or r.status_code != 200:
                continue
            body = r.text or ""
            headers = "\n".join(f"{k}: {v}" for k, v in r.headers.items())
            body_any = ('apiVersion',)
            header_any = ('application/json',)
            if (any(m in body for m in body_any)) and (any(m in headers for m in header_any)):
                self.set_info(
                    severity='critical',
                    reason="Kubernetes Pods - API Discovery & Remote Code Execution detected",
                    path=path,
                )
                return True
        return False

