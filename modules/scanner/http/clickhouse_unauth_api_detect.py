#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Clickhouse API Database is exposed."""

from kittysploit import *
from lib.protocols.http.http_client import Http_client


class Module(Scanner, Http_client):
    __info__ = {
        'name': 'ClickHouse API Database Interface - Improper Authorization Detection',
        'description': 'Clickhouse API Database is exposed.',
        'author': ['KittySploit Team'],
        'severity': 'high',
        'tags': ['web', 'scanner', 'misconfiguration', 'misconfig', 'clickhouse', 'unauth', 'disclosure', 'vuln'],
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
            'https://github.com/luck-ying/Library-POC/blob/master/ClickHouse%E6%95%B0%E6%8D%AE%E5%BA%93/ClickHouse%E6%95%B0%E6%8D%AE%E5%BA%93%208123%E7%AB%AF%E5%8F%A3%E7%9A%84%E6%9C%AA%E6%8E%88%E6%9D%83%E8%AE%BF%E9%97%AE.py',
            'https://github.com/PeiQi0/PeiQi-WIKI-Book/blob/main/docs/redteam/vulnerability/unauthorized/ClickHouse%208123%E7%AB%AF%E5%8F%A3.md?plain=1',
        ],
    }

    def run(self):
        r = self.http_request(method="GET", path='/?query=SHOW%20DATABASES', allow_redirects=False)
        if not r or r.status_code != 200:
            return False
        body = r.text or ""
        headers = "\n".join(f"{k}: {v}" for k, v in r.headers.items())
        body_all = ('default', 'system',)
        header_any = ('text/tab-separated-values',)
        if (all(m in body for m in body_all)) and (any(m in headers for m in header_any)):
            self.set_info(
                severity='high',
                reason="ClickHouse API Database Interface - Improper Authorization detected",
                path='/?query=SHOW%20DATABASES',
            )
            return True
        return False

