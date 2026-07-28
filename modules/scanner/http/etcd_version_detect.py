#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Template detects Etcd version."""

from kittysploit import *
from lib.protocols.http.http_client import Http_client


class Module(Scanner, Http_client):
    __info__ = {
        'name': 'Etcd Version - Detect',
        'description': 'Template detects Etcd version.',
        'author': ['KittySploit Team'],
        'severity': 'info',
        'tags': ['web', 'scanner', 'technology', 'tech', 'k8s', 'kubernetes', 'devops', 'etcd'],
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
        'references': ['https://etcd.io/'],
    }

    def run(self):
        r = self.http_request(method="GET", path='/version', allow_redirects=False)
        if not r or r.status_code != 200:
            return False
        body = r.text or ""
        body_markers = ('"etcdserver"', '"etcdcluster"',)
        body_word_hit = any(m in body for m in body_markers)
        headers = "\n".join(f"{k}: {v}" for k, v in r.headers.items())
        header_markers = ('application/json',)
        if any(m in headers for m in header_markers):
            self.set_info(
                severity='info',
                reason="Etcd Version detected",
                path='/version',
            )
            return True
        return False

