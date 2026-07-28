#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Auerswald COMpact 5500R 7."""

from kittysploit import *
from lib.protocols.http.http_client import Http_client


class Module(Scanner, Http_client):
    __info__ = {
        'name': 'Auerswald COMpact 5500R 7.8A and 8.0B Devices Backdoor Detection',
        'description': 'Auerswald COMpact 5500R 7.8A and 8.0B devices contain an unauthenticated endpoint ("https://192.168.1[.]2/about_state"), enabling the bad actor to gain backdoor access to a web interface that allows for resetting the administrator password.',
        'author': ['KittySploit Team'],
        'severity': 'critical',
        'tags': ['web', 'scanner', 'cve', 'cve2021', 'iot', 'unauth', 'voip', 'auerswald', 'vuln'],
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
            'https://thehackernews.com/2021/12/secret-backdoors-found-in-german-made.html',
            'https://nvd.nist.gov/vuln/detail/CVE-2021-40859',
            'https://www.redteam-pentesting.de/en/advisories/-advisories-publicised-vulnerability-analyses',
            'https://www.redteam-pentesting.de/en/advisories/rt-sa-2021-007/-auerswald-compact-multiple-backdoors',
        ],
        'cve': 'CVE-2021-40859',
    }

    def run(self):
        r = self.http_request(method="GET", path='/about_state', allow_redirects=False)
        if not r or r.status_code != 200:
            return False
        body = r.text or ""
        headers = "\n".join(f"{k}: {v}" for k, v in r.headers.items())
        body_all = ('"pbx"', '"dongleStatus":0', '"macaddr"',)
        header_any = ('application/json',)
        if (all(m in body for m in body_all)) and (any(m in headers for m in header_any)):
            self.set_info(
                severity='critical',
                reason="Auerswald COMpact 5500R 7.8A and 8.0B Devices Backdoor detected",
                path='/about_state',
            )
            return True
        return False

