#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""The COMMAX CCTV Bridge for the DVR service allows an unauthenticated attacker to disclose real time streaming ."""

from kittysploit import *
from lib.protocols.http.http_client import Http_client


class Module(Scanner, Http_client):
    __info__ = {
        'name': 'COMMAX Smart Home Ruvie CCTV Bridge DVR - RTSP Credentials Disclosure Detection',
        'description': 'The COMMAX CCTV Bridge for the DVR service allows an unauthenticated attacker to disclose real time streaming protocol (RTSP) credentials in plain-text.',
        'author': ['KittySploit Team'],
        'severity': 'critical',
        'tags': ['web', 'scanner', 'vulnerability', 'commax', 'exposure', 'camera', 'iot', 'vuln'],
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
        'references': ['https://www.zeroscience.mk/en/vulnerabilities/ZSL-2021-5665.php'],
    }

    def run(self):
        r = self.http_request(method="GET", path='/overview.asp', allow_redirects=False)
        if not r or r.status_code != 200:
            return False
        body = r.text or ""
        body_all = ('DVR Lists', 'rtsp://', 'login_check.js', 'MAX USER :',)
        if (all(m in body for m in body_all)):
            self.set_info(
                severity='critical',
                reason="COMMAX Smart Home Ruvie CCTV Bridge DVR - RTSP Credentials Disclosure detected",
                path='/overview.asp',
            )
            return True
        return False

