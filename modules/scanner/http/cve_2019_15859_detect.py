#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Socomec DIRIS A-40 devices before 48250501 are susceptible to a password disclosure vulnerability in the web i."""

from kittysploit import *
from lib.protocols.http.http_client import Http_client


class Module(Scanner, Http_client):
    __info__ = {
        'name': 'Socomec DIRIS A-40 Devices Password Disclosure Detection',
        'description': 'Socomec DIRIS A-40 devices before 48250501 are susceptible to a password disclosure vulnerability in the web interface that could allow remote attackers to get full access to a device via the /password.jsn URI.',
        'author': ['KittySploit Team'],
        'severity': 'critical',
        'tags': ['web', 'scanner', 'cve', 'cve2019', 'seclists', 'packetstorm', 'disclosure', 'socomec', 'diris', 'iot', 'vuln'],
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
            'https://seclists.org/fulldisclosure/2019/Oct/10',
            'https://nvd.nist.gov/vuln/detail/CVE-2019-15859',
            'http://packetstormsecurity.com/files/154764/Socomec-DIRIS-A-40-Password-Disclosure.html',
            'https://www.socomec.com/single-circuit-multifunction-meters_en.html',
            'http://seclists.org/fulldisclosure/2019/Oct/10',
        ],
        'cve': 'CVE-2019-15859',
    }

    def run(self):
        return False  # disabled: corrupted matchers
        r = self.http_request(method="GET", path='/password.jsn', allow_redirects=False)
        if not r or r.status_code != 200:
            return False
        body = r.text or ""
        headers = "\n".join(f"{k}: {v}" for k, v in r.headers.items())
        body_all = ('username', 'password',)
        header_any = ('text/json',)
        if (all(m in body for m in body_all)) and (any(m in headers for m in header_any)):
            self.set_info(
                severity='critical',
                reason="Socomec DIRIS A-40 Devices Password Disclosure detected",
                path='/password.jsn',
            )
            return True
        return False

