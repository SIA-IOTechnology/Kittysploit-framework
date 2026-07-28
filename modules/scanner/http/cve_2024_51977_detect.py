#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""An unauthenticated attacker who can access either the HTTP service (TCP port 80), the HTTPS service (TCP port ."""

from kittysploit import *
from lib.protocols.http.http_client import Http_client


class Module(Scanner, Http_client):
    __info__ = {
        'name': 'Brother MFC-L9570CDW - Information Disclosure Detection',
        'description': 'An unauthenticated attacker who can access either the HTTP service (TCP port 80), the HTTPS service (TCP port 443), or the IPP service (TCP port 631), can leak several pieces of sensitive information from a vulnerable device. The URI path /etc/mnt_info.csv can be accessed via a GET request and no authentication is required. The returned result is a comma separated value (CSV) table of information. The leaked information includes the device’s model, firmware version, IP address, and serial number.',
        'author': ['KittySploit Team'],
        'severity': 'medium',
        'tags': ['web', 'scanner', 'cve', 'cve2024', 'brother', 'mfc', 'printer', 'exposure', 'vkev', 'vuln'],
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
        'references': ['https://github.com/sfewer-r7/BrotherVulnerabilities/blob/main/CVE-2024-51977.rb'],
        'cve': 'CVE-2024-51977',
    }

    def run(self):
        r = self.http_request(method="GET", path='/etc/mnt_info.csv', allow_redirects=False)
        if not r or r.status_code != 200:
            return False
        body = r.text or ""
        body_any = ('text/comma-separated-values',)
        body_all = ('"Model Name"', '"IP Address"',)
        if (any(m in body for m in body_any)) and (all(m in body for m in body_all)):
            self.set_info(
                severity='medium',
                reason="Brother MFC-L9570CDW - Information Disclosure detected",
                path='/etc/mnt_info.csv',
            )
            return True
        return False

