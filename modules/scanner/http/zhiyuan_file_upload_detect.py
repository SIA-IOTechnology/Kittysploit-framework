#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""A vulnerability in Zhiyuan OA allows remote unauthenticated attackers to upload arbitrary files to the remote ."""

from kittysploit import *
from lib.protocols.http.http_client import Http_client


class Module(Scanner, Http_client):
    __info__ = {
        'name': 'Zhiyuan OA Arbitrary File Upload Vulnerability Detection',
        'description': 'A vulnerability in Zhiyuan OA allows remote unauthenticated attackers to upload arbitrary files to the remote server and cause execute arbitrary code to be executed.',
        'author': ['KittySploit Team'],
        'severity': 'critical',
        'tags': ['web', 'scanner', 'vulnerability', 'zhiyuan', 'rce', 'fileupload', 'seeyon', 'intrusive', 'vuln'],
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
        'references': ['https://www.programmersought.com/article/92658169875/'],
    }

    def run(self):
        r = self.http_request(method="GET", path='/seeyon/thirdpartyController.do.css/..;/ajax.do', allow_redirects=False)
        if not r or r.status_code != 200:
            return False
        body = r.text or ""
        headers = "\n".join(f"{k}: {v}" for k, v in r.headers.items())
        body_any = ('java.lang.NullPointerException:null',)
        header_any = ('text/html',)
        if (any(m in body for m in body_any)) and (any(m in headers for m in header_any)):
            self.set_info(
                severity='critical',
                reason="Zhiyuan OA Arbitrary File Upload Vulnerability detected",
                path='/seeyon/thirdpartyController.do.css/..;/ajax.do',
            )
            return True
        return False

