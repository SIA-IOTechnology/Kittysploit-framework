#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""A vulnerability was found in Mage AI 0."""

from kittysploit import *
from lib.protocols.http.http_client import Http_client


class Module(Scanner, Http_client):
    __info__ = {
        'name': 'Mage AI - Insecure Default Authentication Setup Detection',
        'description': 'A vulnerability was found in Mage AI 0.9.75. It has been classified as problematic. This affects an unknown part. The manipulation leads to insecure default initialization of resource. It is possible to initiate the attack remotely. The complexity of an attack is rather high. The exploitability is told to be difficult. The exploit has been disclosed to the public and may be used. The real existence of this vulnerability is still doubted at the moment. After 7 months of repeated follow-ups by the researcher, Mage AI has decided to not accept this issue as a valid security vulnerability and has confirmed that they will not be addressing it.',
        'author': ['KittySploit Team'],
        'severity': 'medium',
        'tags': ['web', 'scanner', 'cve', 'cve2025', 'mage', 'vuln'],
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
            'https://nvd.nist.gov/vuln/detail/CVE-2025-2129',
            'https://github.com/zn9988/publications/blob/main/2.Mage-AI%20-%20Insecure%20Default%20Authentication%20Setup%20Leading%20to%20Zero-Click%20RCE/README.md',
            'https://vuldb.com/?ctiid.299049',
            'https://vuldb.com/?id.299049',
            'https://vuldb.com/?submit.510690',
        ],
        'cve': 'CVE-2025-2129',
    }

    def run(self):
        r = self.http_request(method="GET", path='/api/kernels', allow_redirects=False)
        if not r or r.status_code != 200:
            return False
        body = r.text or ""
        body_all = ('"kernels": [', '"metadata": {',)
        if (all(m in body for m in body_all)):
            self.set_info(
                severity='medium',
                reason="Mage AI - Insecure Default Authentication Setup detected",
                path='/api/kernels',
            )
            return True
        return False

