#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Symfony profiler was detected."""

from kittysploit import *
from lib.protocols.http.http_client import Http_client


class Module(Scanner, Http_client):
    __info__ = {
        'name': 'Symfony Profiler - Detect',
        'description': 'Symfony profiler was detected.',
        'author': ['KittySploit Team'],
        'severity': 'high',
        'tags': ['web', 'scanner', 'exposure', 'config', 'symfony', 'vuln'],
        'agent': {
            'risk': 'active',
            'effects': ['network_probe'],
            'expected_requests': 6,
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
        'references': ['https://symfony.com/doc/current/profiler.html'],
    }

    def run(self):
        for path in ('/_profiler/empty/search/results?limit=10', '/app_dev.php/_profiler/empty/search/results?limit=10', '/index.php/_profiler/empty/search/results?limit=10', '/index_dev.php/_profiler/empty/search/results?limit=10', '/dev.php/_profiler/empty/search/results?limit=10', '/debug.php/_profiler/empty/search/results?limit=10', '/_debug/_profiler/empty/search/results?limit=10', '/web/_profiler/empty/search/results?limit=10'):
            r = self.http_request(method="GET", path=path, allow_redirects=False)
            if not r or r.status_code != 200:
                continue
            body = r.text or ""
            body_any = ('Symfony Profiler', '<title>Profiler</title>', 'Symfony-Debug-Toolbar',)
            if (any(m in body for m in body_any)):
                self.set_info(
                    severity='high',
                    reason="Symfony Profiler detected",
                    path=path,
                )
                return True
        return False

