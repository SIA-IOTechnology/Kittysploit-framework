#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Detected exposure of the sqlnet."""

from kittysploit import *
from lib.protocols.http.http_client import Http_client


class Module(Scanner, Http_client):
    __info__ = {
        'name': 'Oracle EBS SQL Log - Exposure Detection',
        'description': 'Detected exposure of the sqlnet.log file in Oracle E-Business Suite (EBS), which often contained sensitive information such as database connection details, TNS entries, usernames, and error logs.',
        'author': ['KittySploit Team'],
        'severity': 'medium',
        'tags': ['web', 'scanner', 'exposure', 'oracle', 'ebs', 'log', 'sensitive'],
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
        'references': ['https://the-infosec.com/2017/03/29/do-you-know-what-your-erp-is-telling-us/'],
    }

    def run(self):
        for path in ('/html/bin/sqlnet.log', '/OA_HTML/bin/sqlnet.log'):
            r = self.http_request(method="GET", path=path, allow_redirects=False)
            if not r or r.status_code != 200:
                continue
            body = r.text or ""
            headers = "\n".join(f"{k}: {v}" for k, v in r.headers.items())
            body_all = ('DESCRIPTION=', 'USER=',)
            header_any = ('text/plain',)
            if (all(m in body for m in body_all)) and (any(m in headers for m in header_any)):
                self.set_info(
                    severity='medium',
                    reason="Oracle EBS SQL Log - Exposure detected",
                    path=path,
                )
                return True
        return False

