#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""A Tugboat configuration file was discovered."""

from kittysploit import *
from lib.protocols.http.http_client import Http_client


class Module(Scanner, Http_client):
    __info__ = {
        'name': 'Tugboat Configuration File Exposure Detection',
        'description': 'A Tugboat configuration file was discovered. Tugboat is a command line tool for interacting with DigitalOcean droplets.',
        'author': ['KittySploit Team'],
        'severity': 'critical',
        'tags': ['web', 'scanner', 'exposure', 'tugboat', 'config', 'vuln'],
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
        'references': ['https://github.com/petems/tugboat', 'https://www.digitalocean.com/community/tools/tugboat'],
    }

    def run(self):
        r = self.http_request(method="GET", path='/.tugboat', allow_redirects=False)
        if not r or r.status_code != 200:
            return False
        body = r.text or ""
        body_all = ('authentication', 'access_token', 'ssh_user',)
        if (all(m in body for m in body_all)):
            self.set_info(
                severity='critical',
                reason="Tugboat Configuration File Exposure detected",
                path='/.tugboat',
            )
            return True
        return False

