#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""The LearnPress – WordPress LMS Plugin plugin for WordPress is vulnerable to unauthorized access of data due to."""

from kittysploit import *
from lib.protocols.http.http_client import Http_client


class Module(Scanner, Http_client):
    __info__ = {
        'name': 'LearnPress < 4.3.2 - Broken Access Control Detection',
        'description': "The LearnPress – WordPress LMS Plugin plugin for WordPress is vulnerable to unauthorized access of data due to a missing capability check on the statistic function in all versions up to, and including, 4.3.1. This makes it possible for unauthenticated attackers to view the plugin's orders statistics, including total revenue summaries and order status counts.",
        'author': ['KittySploit Team'],
        'severity': 'medium',
        'tags': ['web', 'scanner', 'cve', 'cve2025', 'wordpress', 'wp-plugin', 'wp', 'learnpress', 'exposure'],
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
                'suggested_followups': [],
            },
        },
        'references': [
            'https://wpscan.com/vulnerability/b4c0e309-45d1-4b00-875d-ec8a76910253/',
            'https://nvd.nist.gov/vuln/detail/CVE-2025-13956',
        ],
        'cve': 'CVE-2025-13956',
    }

    def run(self):
        path = '/wp-json/lp/v1/orders/statistic'
        r = self.http_request(method='GET', path=path, allow_redirects=False)
        if not r or r.status_code != 200:
            return False
        body = r.text or ""
        headers = "\n".join(f"{k}: {v}" for k, v in r.headers.items())
        body_any = ('total-raised', 'order-completed', 'order-pending', 'order-cancelled', 'Total Raised',)
        header_any = ('application/json',)
        if (any(m in body for m in body_any)) and (any(m in headers for m in header_any)):
            self.set_info(
                severity='medium',
                reason='LearnPress < 4.3.2 - Broken Access Control detected',
                path=path,
            )
            return True
        return False

