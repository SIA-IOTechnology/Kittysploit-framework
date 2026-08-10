#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Dahua (and OEM) unauthenticated webCapsConfig information disclosure (CVE-2019-9680)."""

from kittysploit import *
from lib.protocols.http.http_client import Http_client


class Module(Scanner, Http_client):
    __info__ = {
        'name': 'Dahua Devices - webCapsConfig Information Disclosure (CVE-2019-9680)',
        'description': (
            'Multiple Dahua devices (and OEMs) expose /web_caps/webCapsConfig without '
            'authentication, disclosing deviceType and vendor metadata. CVE-2024-13131 was '
            'rejected as a duplicate of CVE-2019-9680.'
        ),
        'author': ['KittySploit Team'],
        'severity': 'medium',
        'tags': [
            'web', 'scanner', 'cve', 'cve2019', 'dahua', 'camera', 'nvr', 'iot',
            'exposure', 'unauth', 'vuln',
        ],
        'agent': {
            'risk': 'active',
            'effects': ['network_probe'],
            'expected_requests': 1,
            'reversible': True,
            'approval_required': False,
            'produces': ['tech_hints', 'risk_signals', 'endpoints'],
            'cost': 1.0,
            'noise': 0.3,
            'value': 0.9,
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
                'produces_capabilities': [{'capability': 'risk_signal', 'from_detail': ''}],
                'consumes_capabilities': [],
                'option_bindings': {},
                'suggested_followups': ['scanner/http/cve_2024_13130_detect'],
            },
        },
        'references': [
            'https://netsecfish.notion.site/IntelBras-IP-Camera-Information-Disclosure-15e6b683e67c80a89f89daf59daa9ea8',
            'https://nvd.nist.gov/vuln/detail/CVE-2019-9680',
        ],
        'cve': 'CVE-2019-9680',
    }

    def run(self):
        path = '/web_caps/webCapsConfig'
        r = self.http_request(method='GET', path=path, allow_redirects=False)
        if not r or r.status_code != 200:
            return False
        body = r.text or ''
        if '"deviceType"' in body and '"vendor"' in body:
            self.set_info(
                severity='medium',
                reason='Dahua CVE-2019-9680 webCapsConfig information disclosure',
                path=path,
            )
            return True
        return False
