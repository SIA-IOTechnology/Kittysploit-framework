#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""A vulnerability is in the 'live_mfg."""

from kittysploit import *
from lib.protocols.http.http_client import Http_client


class Module(Scanner, Http_client):
    __info__ = {
        'name': 'WAVLINK AC1200 - Information Disclosure Detection',
        'description': "A vulnerability is in the 'live_mfg.html' page of the WAVLINK AC1200, version WAVLINK-A42W-1.27.6-20180418, which can allow a remote attacker to access this page without any authentication. When processed, it exposes some key information of the manager of router.",
        'author': ['KittySploit Team'],
        'severity': 'high',
        'tags': ['web', 'scanner', 'cve', 'cve2021', 'wavlink', 'exposure', 'ac1200', 'vuln'],
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
            'https://github.com/zer0yu/CVE_Request/blob/master/WAVLINK/WAVLINK_AC1200_unauthorized_access_vulnerability_first.md',
            'https://nvd.nist.gov/vuln/detail/CVE-2021-44260',
        ],
        'cve': 'CVE-2021-44260',
    }

    def run(self):
        r = self.http_request(method="GET", path='/live_mfg.html', allow_redirects=False)
        if not r or r.status_code != 200:
            return False
        body = r.text or ""
        body_all = ('Model=', 'FW_Version=', 'LAN_MAC=', 'Brand=',)
        if (all(m in body for m in body_all)):
            self.set_info(
                severity='high',
                reason="WAVLINK AC1200 - Information Disclosure detected",
                path='/live_mfg.html',
            )
            return True
        return False

