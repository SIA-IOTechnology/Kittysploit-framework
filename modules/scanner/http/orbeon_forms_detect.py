#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Detects exposed Orbeon Forms interfaces including Form Runner, Form Builder, and Quick Links."""

from kittysploit import *
from lib.protocols.http.http_client import Http_client


class Module(Scanner, Http_client):
    __info__ = {
        'name': 'Orbeon Forms Exposure Detection',
        'description': 'Detects exposed Orbeon Forms interfaces including Form Runner, Form Builder, and Quick Links. Orbeon Forms is a web forms solution that may expose sensitive form data and administrative interfaces if not properly secured.',
        'author': ['KittySploit Team'],
        'severity': 'info',
        'tags': ['web', 'scanner', 'panel', 'exposure', 'orbeon', 'forms', 'form-runner'],
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
        'references': ['https://doc.orbeon.com/', 'https://github.com/orbeon/orbeon-forms'],
    }

    def run(self):
        markers = (
            'Orbeon',
            'home</a>',
            'Quick Links',
        )
        for path in ('/orbeon/', '/'):
            r = self.http_request(method="GET", path=path, allow_redirects=True)
            if not r or r.status_code != 200:
                continue
            body = (r.text or "")
            if any(m in body for m in markers):
                self.set_info(
                    severity='info',
                    reason="Orbeon Forms Exposure detected",
                    path=path,
                )
                return True
        return False

