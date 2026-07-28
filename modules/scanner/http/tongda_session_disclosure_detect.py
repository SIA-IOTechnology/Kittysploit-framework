#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Tongda User session exposed."""

from kittysploit import *
from lib.protocols.http.http_client import Http_client


class Module(Scanner, Http_client):
    __info__ = {
        'name': 'Tongda User Session Disclosure Detection',
        'description': 'Tongda User session exposed.',
        'author': ['KittySploit Team'],
        'severity': 'medium',
        'tags': ['web', 'scanner', 'vulnerability', 'tongda', 'disclosure', 'vuln'],
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
        'references': ['https://mp.weixin.qq.com/s/llyGEBRo0t-C7xOLMDYfFQ'],
    }

    def run(self):
        path = '/general/userinfo.php?UID=1'
        r = self.http_request(method='POST', path=path, allow_redirects=False)
        if not r or r.status_code != 200:
            return False
        body = r.text or ""
        headers = "\n".join(f"{k}: {v}" for k, v in r.headers.items())
        body_all = ('"dept_name":"', '"online_flag":',)
        header_all = ('application/json',)
        if (all(m in body for m in body_all)) and (all(m in headers for m in header_all)):
            self.set_info(
                severity='medium',
                reason='Tongda User Session Disclosure detected',
                path=path,
            )
            return True
        return False

