#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Detects Fortra FileCatalyst web interfaces that allow anonymous or guest access."""

from kittysploit import *
from lib.protocols.http.http_client import Http_client


class Module(Scanner, Http_client):
    __info__ = {
        'name': 'Fortra FileCatalyst - Anonymous Access Detection',
        'description': 'Detects Fortra FileCatalyst web interfaces that allow anonymous or guest access. FileCatalyst is a managed file transfer solution, and anonymous access to its portal can expose sensitive files and configuration if not properly secured. This template checks for publicly accessible instances with guest or unauthenticated user functionality.',
        'author': ['KittySploit Team'],
        'severity': 'low',
        'tags': ['web', 'scanner', 'misconfiguration', 'filecatalyst', 'fortra', 'anonymous', 'exposure', 'misconfig'],
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
            'https://www.fortra.com/products/filecatalyst',
            'https://www.fortra.com/products/filecatalyst/resources/security-best-practices',
        ],
    }

    def run(self):
        r = self.http_request(method="GET", path='/workflow/jsp/downloadFiles.jsp', allow_redirects=True)
        if not r or r.status_code != 200:
            return False
        body = r.text or ""
        body_all = ('</i>Guest', 'Logout</a>', 'FileCatalyst',)
        if (all(m in body for m in body_all)):
            self.set_info(
                severity='low',
                reason="Fortra FileCatalyst - Anonymous Access detected",
                path='/workflow/jsp/downloadFiles.jsp',
            )
            return True
        return False

