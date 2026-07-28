#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Detected exposed OVHcloud backup configuration files (ovh-backups."""

from kittysploit import *
from lib.protocols.http.http_client import Http_client


class Module(Scanner, Http_client):
    __info__ = {
        'name': 'OVHcloud Backup Configuration - Exposure Detection',
        'description': 'Detected exposed OVHcloud backup configuration files (ovh-backups.json) containing sensitive credentials such as OpenStack/Swift authentication details, API keys, and storage configuration.',
        'author': ['KittySploit Team'],
        'severity': 'high',
        'tags': ['web', 'scanner', 'exposure', 'ovh', 'ovhcloud', 'backup', 'config', 'cloud', 'openstack'],
        'agent': {
            'risk': 'active',
            'effects': ['network_probe'],
            'expected_requests': 4,
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
            'https://docs.ovh.com/gb/en/storage/',
            'https://docs.ovh.com/gb/en/public-cloud/access_and_security_in_horizon/',
        ],
    }

    def run(self):
        for path in ('/ovh-backups.json', '/config/ovh-backups.json', '/backup/ovh-backups.json', '/storage/ovh-backups.json'):
            r = self.http_request(method="GET", path=path, allow_redirects=False)
            if not r or r.status_code != 200:
                continue
            body = r.text or ""
            body_any = ('application/json',)
            body_all = ('accessKey', 'secretKey',)
            if (any(m in body for m in body_any)) and (all(m in body for m in body_all)):
                self.set_info(
                    severity='high',
                    reason="OVHcloud Backup Configuration - Exposure detected",
                    path=path,
                )
                return True
        return False

