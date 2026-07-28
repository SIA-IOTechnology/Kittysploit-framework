#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Detected exposed PEAR registry files (."""

from kittysploit import *
from lib.protocols.http.http_client import Http_client


class Module(Scanner, Http_client):
    __info__ = {
        'name': 'PEAR Registry Files Exposed Detection',
        'description': 'Detected exposed PEAR registry files (.reg) containing serialized PHP metadata, including package versions and local paths. This exposure facilitated supply-chain reconnaissance by revealing installed dependencies and system mappings.',
        'author': ['KittySploit Team'],
        'severity': 'low',
        'tags': ['web', 'scanner', 'exposure', 'misconfig', 'pear', 'php', 'registry'],
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
            'https://pear.php.net/manual/en/core.pear.pear-registry.php',
            'https://github.com/pear/pear-core/blob/master/PEAR/Registry.php',
            'https://blog.sonarsource.com/php-supply-chain-attack-on-pear/',
        ],
    }

    def run(self):
        for path in ('/.registry/pear.reg.ber', '/.registry/pear.reg', '/PEAR/.registry/pear.reg.ber', '/PEAR/.registry/pear.reg'):
            r = self.http_request(method="GET", path=path, allow_redirects=False)
            if not r or r.status_code != 200:
                continue
            body = r.text or ""
            body_all = ('install-pear.php', 'PEAR_ErrorStack', 'install-pear-nozlib.phar',)
            if (all(m in body for m in body_all)):
                self.set_info(
                    severity='low',
                    reason="PEAR Registry Files Exposed detected",
                    path=path,
                )
                return True
        return False

