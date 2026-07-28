#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""VICIdial's Web Client is susceptible to information disclosure because it contains many sensitive files that c."""

from kittysploit import *
from lib.protocols.http.http_client import Http_client


class Module(Scanner, Http_client):
    __info__ = {
        'name': 'VICIdial Sensitive Information Disclosure Detection',
        'description': "VICIdial's Web Client is susceptible to information disclosure because it contains many sensitive files that can be accessed from the client side. These files contain mysqli logs, auth logs, debug information, successful and unsuccessful login attempts with their corresponding IP's, User-Agents, credentials and much more. This information can be leveraged by an attacker to gain further access to VICIdial systems.",
        'author': ['KittySploit Team'],
        'severity': 'high',
        'tags': ['web', 'scanner', 'cve', 'cve2021', 'sqli', 'vuln'],
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
        'references': ['https://github.com/JHHAX/VICIdial'],
        'cve': 'CVE-2021-28854',
    }

    def run(self):
        r = self.http_request(method="GET", path='/agc/vicidial_mysqli_errors.txt', allow_redirects=False)
        if not r or r.status_code != 200:
            return False
        body = r.text or ""
        headers = "\n".join(f"{k}: {v}" for k, v in r.headers.items())
        body_any = ('vdc_db_query',)
        header_any = ('text/plain',)
        if (any(m in body for m in body_any)) and (any(m in headers for m in header_any)):
            self.set_info(
                severity='high',
                reason="VICIdial Sensitive Information Disclosure detected",
                path='/agc/vicidial_mysqli_errors.txt',
            )
            return True
        return False

