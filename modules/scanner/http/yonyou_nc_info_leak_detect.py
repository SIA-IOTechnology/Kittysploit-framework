#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""After logging in and visiting the address where the information was leaked, you will have permission to upload."""

from kittysploit import *
from lib.protocols.http.http_client import Http_client


class Module(Scanner, Http_client):
    __info__ = {
        'name': 'Yonyou UFIDA NC - Information Exposure Detection',
        'description': 'After logging in and visiting the address where the information was leaked, you will have permission to upload files. Then just go back to the homepage and view the published content directly.',
        'author': ['KittySploit Team'],
        'severity': 'medium',
        'tags': ['web', 'scanner', 'vulnerability', 'yonyou', 'nc', 'exposure', 'vuln'],
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
            'https://mp.weixin.qq.com/s/Lu6Zd9LP3PQsb8uzTIcANQ',
            'https://github.com/zhangzhenfeng/AnyScan/blob/master/AnyScanUI/AnyPoc/data/poc/bugscan/exp%EF%BC%8D2311.py',
        ],
    }

    def run(self):
        r = self.http_request(method="GET", path='/service/~iufo/com.ufida.web.action.ActionServlet?TableSelectedID&TreeSelectedID&action=nc.ui.iufo.release.InfoReleaseAction&method=createBBSRelease', allow_redirects=False)
        if not r or r.status_code != 200:
            return False
        body = r.text or ""
        body_all = ('iufo/web/images/usericon.gif', '/iufo/web/images/tree/tree_plus.gif',)
        if (all(m in body for m in body_all)):
            self.set_info(
                severity='medium',
                reason="Yonyou UFIDA NC - Information Exposure detected",
                path='/service/~iufo/com.ufida.web.action.ActionServlet?TableSelectedID&TreeSelectedID&action=nc.ui.iufo.release.InfoReleaseAction&method=createBBSRelease',
            )
            return True
        return False

