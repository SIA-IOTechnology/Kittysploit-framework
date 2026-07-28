#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Alibaba Cloud Object Storage Service (OSS) bucket is publicly accessible and allows anonymous listing of objec."""

from kittysploit import *
from lib.protocols.http.http_client import Http_client


class Module(Scanner, Http_client):
    __info__ = {
        'name': 'Alibaba Cloud OSS Bucket - Public Listing Enabled Detection',
        'description': 'Alibaba Cloud Object Storage Service (OSS) bucket is publicly accessible and allows anonymous listing of objects. This misconfiguration can expose sensitive data, lead to data breaches, and result in unexpected charges on the Alibaba Cloud bill.',
        'author': ['KittySploit Team'],
        'severity': 'info',
        'tags': ['web', 'scanner', 'misconfiguration', 'alibaba', 'cloud', 'bucket', 'misconfig', 'exposure', 'devops', 'cicd'],
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
            'https://www.alibabacloud.com/help/en/oss/user-guide/block-public-access',
            'https://www.trendmicro.com/cloudoneconformity/knowledge-base/alibaba-cloud/AlibabaCloud-OSS/publicly-accessible-oss-bucket.html',
        ],
    }

    def run(self):
        r = self.http_request(method="GET", path='/', allow_redirects=False)
        if not r or r.status_code != 200:
            return False
        body = r.text or ""
        headers = "\n".join(f"{k}: {v}" for k, v in r.headers.items())
        body_any = ('application/xml',)
        body_all = ('<ListBucketResult', '<Name>', '<Contents>', '<Key>',)
        header_any = ('AliyunOSS',)
        if (any(m in body for m in body_any)) and (all(m in body for m in body_all)) and (any(m in headers for m in header_any)):
            self.set_info(
                severity='info',
                reason="Alibaba Cloud OSS Bucket - Public Listing Enabled detected",
                path='/',
            )
            return True
        return False

