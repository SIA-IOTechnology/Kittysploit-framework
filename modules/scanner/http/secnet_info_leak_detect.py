#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Secnet Intelligent Routing System is exposed."""

from kittysploit import *
from lib.protocols.http.http_client import Http_client


class Module(Scanner, Http_client):
    __info__ = {
        'name': 'Secnet Intelligent Routing System actpt_5g.data - Information Leak Detection',
        'description': 'Secnet Intelligent Routing System is exposed.',
        'author': ['KittySploit Team'],
        'severity': 'high',
        'tags': ['web', 'scanner', 'misconfiguration', 'info-leak', 'secnet', 'misconfig', 'vuln'],
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
            'https://mp.weixin.qq.com/s/lNlI5ZtUJG50ipS0WfytUw',
            'https://github.com/gobysec/GobyVuls/blob/master/secnet_Intelligent_Router_actpt_5g.data_Infoleakage.md',
        ],
    }

    def run(self):
        r = self.http_request(method="GET", path='/actpt_5g.data', allow_redirects=False)
        if not r or r.status_code != 200:
            return False
        body = r.text or ""
        body_all = ('"http_username":', '"http_passwd":',)
        if (all(m in body for m in body_all)):
            self.set_info(
                severity='high',
                reason="Secnet Intelligent Routing System actpt_5g.data - Information Leak detected",
                path='/actpt_5g.data',
            )
            return True
        return False

