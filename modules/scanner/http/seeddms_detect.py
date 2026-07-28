#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""SeedDMS login panel was detected."""

from kittysploit import *
from lib.protocols.http.http_client import Http_client


class Module(Scanner, Http_client):
    __info__ = {
        'name': 'SeedDMS Login Panel - Detect',
        'description': 'SeedDMS login panel was detected.',
        'author': ['KittySploit Team'],
        'severity': 'info',
        'tags': ['web', 'scanner', 'panel', 'seeddms', 'login'],
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
    }

    def run(self):
        markers = (
            'href="/out/out.ViewFolder.php">SeedDMS</a>',
            'href="../out/out.ViewFolder.php?folderid=1">SeedDMS</a>',
        )
        for path in ('/out/out.Login.php?referuri=%2Fout%2Fout.ViewFolder.php', '/dms/out/out.Login.php?referuri=%2Fout%2Fout.ViewFolder.php'):
            r = self.http_request(method="GET", path=path, allow_redirects=True)
            if not r or r.status_code != 200:
                continue
            body = (r.text or "")
            if any(m in body for m in markers):
                self.set_info(
                    severity='info',
                    reason="SeedDMS Login Panel detected",
                    path=path,
                )
                return True
        return False

