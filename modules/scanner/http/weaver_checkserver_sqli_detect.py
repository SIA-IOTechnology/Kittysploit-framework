#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Ecology OA system improperly filters incoming data from users, resulting in a SQL injection vulnerability."""

from kittysploit import *
from lib.protocols.http.http_client import Http_client


class Module(Scanner, Http_client):
    __info__ = {
        'name': 'Ecology OA CheckServer - SQL Injection Detection',
        'description': 'Ecology OA system improperly filters incoming data from users, resulting in a SQL injection vulnerability. Remote and unauthenticated attackers can use this vulnerability to conduct SQL injection attacks and steal sensitive database information.',
        'author': ['KittySploit Team'],
        'severity': 'high',
        'tags': ['web', 'scanner', 'vulnerability', 'weaver', 'ecology', 'sqli', 'vuln'],
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
            'https://stack.chaitin.com/techblog/detail?id=81',
            'https://github.com/lal0ne/vulnerability/blob/main/%E6%B3%9B%E5%BE%AE/E-Cology/CheckServer/README.md',
            'https://github.com/zan8in/afrog/blob/main/v2/pocs/afrog-pocs/vulnerability/weaver-ecology-oa-plugin-checkserver-setting-sqli.yaml',
        ],
    }

    def run(self):
        r = self.http_request(method="GET", path='/mobile/plugin/CheckServer.jsp?type=mobileSetting', allow_redirects=False)
        if not r or r.status_code != 200:
            return False
        body = r.text or ""
        headers = "\n".join(f"{k}: {v}" for k, v in r.headers.items())
        body_any = ('error\\":\\"system error', 'securityIntercept',)
        header_all = ('application/json', 'ecology_',)
        if (any(m in body for m in body_any)) and (all(m in headers for m in header_all)):
            self.set_info(
                severity='high',
                reason="Ecology OA CheckServer - SQL Injection detected",
                path='/mobile/plugin/CheckServer.jsp?type=mobileSetting',
            )
            return True
        return False

