#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""PaperCut NG allows for unauthenticated XMLRPC commands to be run by default."""

from kittysploit import *
from lib.protocols.http.http_client import Http_client


class Module(Scanner, Http_client):
    __info__ = {
        'name': 'PaperCut NG Unauthenticated XMLRPC Functionality Detection',
        'description': 'PaperCut NG allows for unauthenticated XMLRPC commands to be run by default. Versions 22.0.12 and below are confirmed to be affected, but later versions may also be affected due to lack of a vendor supplied patch.',
        'author': ['KittySploit Team'],
        'severity': 'medium',
        'tags': ['web', 'scanner', 'cve2023', 'cve', 'unauth', 'papercut', 'vuln'],
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
            'https://nvd.nist.gov/vuln/detail/CVE-2023-4568',
            'https://www.tenable.com/security/research/tra-2023-31',
        ],
        'cve': 'CVE-2023-4568',
    }

    def run(self):
        path = '/rpc/clients/xmlrpc'
        r = self.http_request(method='POST', path=path, allow_redirects=False, headers={'Content-Type': 'text/xml'}, data='<?xml version="1.0"?><methodCall><methodName>client.getGlobalConfig</methodName><params><param><value><string>str1</string></value></param><param><value><string>str2</string></value></param></params></methodCall>\n')
        if not r or r.status_code != 200:
            return False
        body = r.text or ""
        headers = "\n".join(f"{k}: {v}" for k, v in r.headers.items())
        body_all = ('conf.ssl-port', 'conf.auth-ttl-default',)
        header_any = ('text/xml',)
        if (all(m in body for m in body_all)) and (any(m in headers for m in header_any)):
            self.set_info(severity='medium', reason='PaperCut NG Unauthenticated XMLRPC Functionality detected', path=path)
            return True
        return False

