#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""A Docker container misconfiguration was discovered."""

from kittysploit import *
from lib.protocols.http.http_client import Http_client


class Module(Scanner, Http_client):
    __info__ = {
        'name': 'Docker Container - Misconfiguration Exposure Detection',
        'description': 'A Docker container misconfiguration was discovered. The Docker daemon can listen for Docker Engine API requests via three different types of Socket - unix, tcp, and fd. With tcp enabled, the default setup provides un-encrypted and un-authenticated direct access to the Docker daemon. It is conventional to use port 2375 for un-encrypted, and port 2376 for encrypted communication with the daemon.',
        'author': ['KittySploit Team'],
        'severity': 'critical',
        'tags': ['web', 'scanner', 'misconfiguration', 'misconfig', 'docker', 'unauth', 'devops', 'vuln'],
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
            'https://madhuakula.com/content/attacking-and-auditing-docker-containers-using-opensource/attacking-docker-containers/misconfiguration.html',
        ],
    }

    def run(self):
        r = self.http_request(method="GET", path='/images/json', allow_redirects=False)
        if not r or r.status_code != 200:
            return False
        body = r.text or ""
        body_all = ('"ParentId":', '"Containers":', '"Labels":',)
        if (all(m in body for m in body_all)):
            self.set_info(
                severity='critical',
                reason="Docker Container - Misconfiguration Exposure detected",
                path='/images/json',
            )
            return True
        return False

