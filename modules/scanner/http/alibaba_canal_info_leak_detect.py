#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Alibaba Canal configuration information was detected."""

from kittysploit import *
from lib.protocols.http.http_client import Http_client


class Module(Scanner, Http_client):
    __info__ = {
        'name': 'Alibaba Canal Config - Detect',
        'description': 'Alibaba Canal configuration information was detected.',
        'author': ['KittySploit Team'],
        'severity': 'info',
        'tags': ['web', 'scanner', 'exposure', 'config', 'alibaba', 'vuln'],
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
            'https://github.com/alibaba/canal/issues/632',
            'https://netty.io/wiki/reference-counted-objects.html',
            'https://my.oschina.net/u/4581879/blog/4753320',
        ],
    }

    def run(self):
        r = self.http_request(method="GET", path='/api/v1/canal/config/1/1', allow_redirects=False)
        if not r or r.status_code != 200:
            return False
        body = r.text or ""
        headers = "\n".join(f"{k}: {v}" for k, v in r.headers.items())
        body_all = ('ncanal.aliyun.accessKey', 'ncanal.aliyun.secretKey',)
        header_all = ('application/json',)
        if (all(m in body for m in body_all)) and (all(m in headers for m in header_all)):
            self.set_info(
                severity='info',
                reason="Alibaba Canal Config detected",
                path='/api/v1/canal/config/1/1',
            )
            return True
        return False

