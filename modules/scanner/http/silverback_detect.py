#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Detects Silverback MDM - Detection."""

from kittysploit import *
from lib.protocols.http.http_client import Http_client
from lib.osint.favicon_hash import shodan_mmh3


class Module(Scanner, Http_client):
    __info__ = {
        'name': 'Silverback MDM - Detection',
        'description': 'Detects Silverback MDM - Detection.',
        'author': ['KittySploit Team'],
        'severity': 'info',
        'tags': ['web', 'scanner', 'technology', 'favicon', 'tech', 'silverback', 'mdm'],
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
            'https://help.matrix42.com/010_SUEM/020_UEM/30Enterprise_Mobility_Management/010Installation_and_Update/10_Silverback',
        ],
    }

    def run(self):
        r = self.http_request(method="GET", path='/sts/Content/Images/favicon.ico', allow_redirects=False)
        if not r or r.status_code != 200:
            return False
        mmh3_vals = ('635899646',)
        if (shodan_mmh3(r.content or b"") in mmh3_vals):
            self.set_info(
                severity='info',
                reason="Silverback MDMion detected",
                path='/sts/Content/Images/favicon.ico',
            )
            return True
        return False

