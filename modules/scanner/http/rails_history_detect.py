#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Detects exposure of Ruby/Rails console history files (."""

from kittysploit import *
from lib.protocols.http.http_client import Http_client


class Module(Scanner, Http_client):
    __info__ = {
        'name': 'Rails/Ruby Console History - Exposure Detection',
        'description': 'Detects exposure of Ruby/Rails console history files (.irb_history and .pry_history) via HTTP. Leakage of these files may disclose sensitive code, credentials, or insight into application logic, increasing the risk of unauthorized access or exploitation.',
        'author': ['KittySploit Team'],
        'severity': 'medium',
        'tags': ['web', 'scanner', 'exposure', 'rails', 'ruby', 'config'],
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
        'references': ['https://pry.github.io', 'https://docs.ruby-lang.org/en/2.6.0/IRB.html'],
    }

    def run(self):
        for path in ('/.irb_history', '/.pry_history'):
            r = self.http_request(method="GET", path=path, allow_redirects=False)
            if not r or r.status_code != 200:
                continue
            body = r.text or ""
            body_any = ('<!DOCTYPE', '<html', '<script>',)
            body_all = ('User.find', 'Rails.application',)
            if (any(m in body for m in body_any)) and (all(m in body for m in body_all)):
                self.set_info(
                    severity='medium',
                    reason="Rails/Ruby Console History - Exposure detected",
                    path=path,
                )
                return True
        return False

