#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Microsoft SharePoint is vulnerable to a remote code execution when the software fails to check the source mark."""

import re
from kittysploit import *
from lib.protocols.http.http_client import Http_client


class Module(Scanner, Http_client):
    __info__ = {
        'name': 'Microsoft SharePoint - Remote Code Execution Detection',
        'description': 'Microsoft SharePoint is vulnerable to a remote code execution when the software fails to check the source markup of an application package.',
        'author': ['KittySploit Team'],
        'severity': 'high',
        'tags': ['web', 'scanner', 'cve', 'cve2020', 'msf', 'sharepoint', 'iis', 'microsoft', 'ssi', 'rce', 'vuln'],
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
            'https://srcincite.io/pocs/cve-2020-16952.py.txt',
            'https://portal.msrc.microsoft.com/en-US/security-guidance/advisory/CVE-2020-16952',
            'https://github.com/rapid7/metasploit-framework/blob/1a341ae93191ac5f6d8a9603aebb6b3a1f65f107/documentation/modules/exploit/windows/http/sharepoint_ssi_viewstate.md',
            'https://nvd.nist.gov/vuln/detail/CVE-2020-16952',
            'https://github.com/ARPSyndicate/cvemon',
        ],
        'cve': 'CVE-2020-16952',
    }

    def run(self):
        r = self.http_request(method="GET", path='/', allow_redirects=False)
        if not r or r.status_code not in (200, 201):
            return False
        body = r.text or ""
        headers = "\n".join(f"{k}: {v}" for k, v in r.headers.items())
        body_regexes = ('15\\.0\\.0\\.(4571|5275|4351|5056)', '16\\.0\\.0\\.(10337|10364|10366)',)
        header_regexes = ('(?i)(Microsoftsharepointteamservices:)',)
        if (any(re.search(rx, body, 0) for rx in body_regexes)) and (any(re.search(rx, headers, 0) for rx in header_regexes)):
            self.set_info(
                severity='high',
                reason="Microsoft SharePoint - Remote Code Execution detected",
                path='/',
            )
            return True
        return False

