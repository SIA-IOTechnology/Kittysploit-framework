#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""qdPM 9."""

from kittysploit import *
from lib.protocols.http.http_client import Http_client


class Module(Scanner, Http_client):
    __info__ = {
        'name': 'qdPM 9.2 - Directory Traversal Detection',
        'description': 'qdPM 9.2 allows Directory Traversal to list files and directories by navigating to the /uploads URI.',
        'author': ['KittySploit Team'],
        'severity': 'high',
        'tags': ['web', 'scanner', 'cve', 'cve2023', 'qdpm', 'lfi', 'vuln'],
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
            'https://github.com/SunshineOtaku/Report-CVE/blob/main/qdPM/9.2/Directory%20Traversal.md',
            'https://nvd.nist.gov/vuln/detail/CVE-2023-45855',
            'https://qdpm.net',
        ],
        'cve': 'CVE-2023-45855',
    }

    def run(self):
        r = self.http_request(method="GET", path='/uploads/', allow_redirects=False)
        if not r or r.status_code != 200:
            return False
        body = r.text or ""
        body_all = ('Index of /uploads</title>', 'attachments/</a>',)
        if (all(m in body for m in body_all)):
            self.set_info(
                severity='high',
                reason="qdPM 9.2 - Directory Traversal detected",
                path='/uploads/',
            )
            return True
        return False

