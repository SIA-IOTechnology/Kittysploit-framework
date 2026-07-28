#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""PbootCMS 2."""

from kittysploit import *
from lib.protocols.http.http_client import Http_client


class Module(Scanner, Http_client):
    __info__ = {
        'name': 'PbootCMS 2.0.7 - SQL Injection Detection',
        'description': 'PbootCMS 2.0.7 contains a SQL injection vulnerability via pbootcms.db. An attacker can possibly obtain sensitive information from a database, modify data, and execute unauthorized administrative operations in the context of the affected site.',
        'author': ['KittySploit Team'],
        'severity': 'critical',
        'tags': ['web', 'scanner', 'vulnerability', 'pbootcms', 'db', 'exposure', 'database', 'sqlite', 'sqli', 'vuln'],
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
        'references': ['https://xz.aliyun.com/t/7628', 'https://www.cnblogs.com/0daybug/p/12786036.html'],
    }

    def run(self):
        r = self.http_request(method="GET", path='/data/pbootcms.db', allow_redirects=False)
        if not r or r.status_code != 200:
            return False
        body = r.text or ""
        body_all = ('PbootCMS', 'SQLite format 3',)
        if (all(m in body for m in body_all)):
            self.set_info(
                severity='critical',
                reason="PbootCMS 2.0.7 - SQL Injection detected",
                path='/data/pbootcms.db',
            )
            return True
        return False

