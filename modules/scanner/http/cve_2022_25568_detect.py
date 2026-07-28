#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""MotionEye v0."""

from kittysploit import *
from lib.protocols.http.http_client import Http_client


class Module(Scanner, Http_client):
    __info__ = {
        'name': 'MotionEye Config Info Disclosure Detection',
        'description': 'MotionEye v0.42.1 and below allows attackers to access sensitive information via a GET request to /config/list. To exploit this vulnerability, a regular user password must be unconfigured.',
        'author': ['KittySploit Team'],
        'severity': 'high',
        'tags': ['web', 'scanner', 'cve', 'cve2022', 'motioneye', 'config', 'motioneye_project', 'vuln'],
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
            'https://www.pizzapower.me/2022/02/17/motioneye-config-info-disclosure/',
            'https://github.com/ccrisan/motioneye/issues/2292',
            'https://nvd.nist.gov/vuln/detail/cve-2022-25568',
            'https://github.com/KayCHENvip/vulnerability-poc',
            'https://github.com/Miraitowa70/POC-Notes',
        ],
        'cve': 'CVE-2022-25568',
    }

    def run(self):
        r = self.http_request(method="GET", path='/config/list', allow_redirects=False)
        if not r or r.status_code != 200:
            return False
        body = r.text or ""
        headers = "\n".join(f"{k}: {v}" for k, v in r.headers.items())
        body_all = ('upload_password', 'network_password',)
        header_any = ('application/json',)
        if (all(m in body for m in body_all)) and (any(m in headers for m in header_any)):
            self.set_info(
                severity='high',
                reason="MotionEye Config Info Disclosure detected",
                path='/config/list',
            )
            return True
        return False

