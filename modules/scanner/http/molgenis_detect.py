#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Molgenis emx2 data platform is a software that provides a web-based interface for managing and analyzing data."""

from kittysploit import *
from lib.protocols.http.http_client import Http_client


class Module(Scanner, Http_client):
    __info__ = {
        'name': 'Molgenis Panel - Exposure Detection',
        'description': 'Molgenis emx2 data platform is a software that provides a web-based interface for managing and analyzing data. It might contain sensitive information without authentication.',
        'author': ['KittySploit Team'],
        'severity': 'info',
        'tags': ['web', 'scanner', 'panel', 'molgenis', 'login', 'emx2'],
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
        'references': ['https://molgenis.org/', 'https://github.com/molgenis/molgenis-emx2'],
    }

    def run(self):
        for path in ('/', '/api'):
            r = self.http_request(method="GET", path=path, allow_redirects=True)
            if not r or r.status_code != 200:
                continue
            body = r.text or ""
            body_markers = (
                'molgenis-',
                'Welcome to MOLGENIS EMX2 POC',
            )
            if any(m in body for m in body_markers):
                self.set_info(
                    severity='info',
                    reason="Molgenis Panel - Exposure detected",
                    path=path,
                )
                return True
        return False

