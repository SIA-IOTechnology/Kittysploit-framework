#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Wanhu OA officeserverservlet file upload vulnerability."""

from kittysploit import *
from lib.protocols.http.http_client import Http_client


class Module(Scanner, Http_client):
    __info__ = {
        'name': 'Wanhu OA OfficeServerServlet - Arbitrary File Upload Detection',
        'description': 'Wanhu OA officeserverservlet file upload vulnerability',
        'author': ['KittySploit Team'],
        'severity': 'critical',
        'tags': ['web', 'scanner', 'vulnerability', 'wanhu', 'oa', 'officeserver', 'fileupload', 'intrusive', 'vuln'],
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
            'https://github.com/onMey/WH/blob/main/poc.py',
            'http://wiki.peiqi.tech/wiki/oa/万户OA/万户OA%20OfficeServer.jsp%20任意文件上传漏洞.html',
        ],
    }

    def run(self):
        r = self.http_request(method="GET", path='/defaultroot/officeserverservlet', allow_redirects=False)
        if not r or r.status_code != 200:
            return False
        body = r.text or ""
        body_all = ('DBSTEP V3.0', 'Post',)
        if (all(m in body for m in body_all)):
            self.set_info(
                severity='critical',
                reason="Wanhu OA OfficeServerServlet - Arbitrary File Upload detected",
                path='/defaultroot/officeserverservlet',
            )
            return True
        return False

