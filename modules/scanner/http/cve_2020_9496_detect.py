#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Apache OFBiz 17."""

from kittysploit import *
from lib.protocols.http.http_client import Http_client


class Module(Scanner, Http_client):
    __info__ = {
        'name': 'Apache OFBiz 17.12.03 - Cross-Site Scripting Detection',
        'description': 'Apache OFBiz 17.12.03 contains cross-site scripting and unsafe deserialization vulnerabilities via an XML-RPC request.',
        'author': ['KittySploit Team'],
        'severity': 'medium',
        'tags': ['web', 'scanner', 'cve', 'cve2020', 'ofbiz', 'packetstorm', 'apache', 'java', 'vkev', 'vuln'],
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
            'http://packetstormsecurity.com/files/158887/Apache-OFBiz-XML-RPC-Java-Deserialization.html',
            'http://packetstormsecurity.com/files/161769/Apache-OFBiz-XML-RPC-Java-Deserialization.html',
            'https://securitylab.github.com/advisories/GHSL-2020-069-apache_ofbiz',
            'https://s.apache.org/l0994',
            'https://nvd.nist.gov/vuln/detail/CVE-2020-9496',
        ],
        'cve': 'CVE-2020-9496',
    }

    def run(self):
        path = '/webtools/control/xmlrpc'
        r = self.http_request(method='POST', path=path, allow_redirects=False, headers={'Origin': 'http://{{Hostname}}', 'Content-Type': 'application/xml'}, data='<?xml version="1.0"?><methodCall><methodName>ProjectDiscovery</methodName><params><param><value>dwisiswant0</value></param></params></methodCall>\n')
        if not r or r.status_code != 200:
            return False
        body = r.text or ""
        headers = "\n".join(f"{k}: {v}" for k, v in r.headers.items())
        body_all = ('faultString', 'No such service [ProjectDiscovery]', 'methodResponse',)
        header_any = ('Content-Type: text/xml',)
        if (all(m in body for m in body_all)) and (any(m in headers for m in header_any)):
            self.set_info(severity='medium', reason='Apache OFBiz 17.12.03 - Cross-Site Scripting detected', path=path)
            return True
        return False

