#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Sensitive info disclosed in Caucho Resin."""

from kittysploit import *
from lib.protocols.http.http_client import Http_client


class Module(Scanner, Http_client):
    __info__ = {
        'name': 'Caucho Resin Information Disclosure Detection',
        'description': 'Sensitive info disclosed in Caucho Resin.',
        'author': ['KittySploit Team'],
        'severity': 'high',
        'tags': ['web', 'scanner', 'vulnerability', 'resin', 'caucho', 'lfr', 'vuln'],
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
        'references': ['http://www.cnnvd.org.cn/web/xxk/ldxqById.tag?CNNVD=CNNVD-200705-315'],
    }

    def run(self):
        r = self.http_request(method="GET", path='/%20../web-inf/', allow_redirects=False)
        if not r or r.status_code != 200:
            return False
        body = r.text or ""
        body_all = ('/ ../web-inf/', 'Directory of /',)
        if (all(m in body for m in body_all)):
            self.set_info(
                severity='high',
                reason="Caucho Resin Information Disclosure detected",
                path='/%20../web-inf/',
            )
            return True
        return False

