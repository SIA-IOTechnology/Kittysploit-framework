#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""UEditor contains an arbitrary file upload vulnerability."""

from kittysploit import *
from lib.protocols.http.http_client import Http_client


class Module(Scanner, Http_client):
    __info__ = {
        'name': 'UEditor - Arbitrary File Upload Detection',
        'description': 'UEditor contains an arbitrary file upload vulnerability. An attacker can upload arbitrary files to the server, which in turn can be used to make the application execute file content as code, As a result, an attacker can possibly obtain sensitive information, modify data, and/or execute unauthorized operations.',
        'author': ['KittySploit Team'],
        'severity': 'high',
        'tags': ['web', 'scanner', 'vulnerability', 'ueditor', 'fileupload', 'intrusive', 'vuln'],
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
        'references': ['https://zhuanlan.zhihu.com/p/85265552', 'https://www.freebuf.com/vuls/181814.html'],
    }

    def run(self):
        r = self.http_request(method="GET", path='/ueditor/net/controller.ashx?action=catchimage&encode=utf-8', allow_redirects=False)
        if not r or r.status_code != 200:
            return False
        body = r.text or ""
        body_any = ('没有指定抓取源',)
        if (any(m in body for m in body_any)):
            self.set_info(
                severity='high',
                reason="UEditor - Arbitrary File Upload detected",
                path='/ueditor/net/controller.ashx?action=catchimage&encode=utf-8',
            )
            return True
        return False

