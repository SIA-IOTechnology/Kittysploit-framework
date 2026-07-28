#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""iSpy 7."""

from kittysploit import *
from lib.protocols.http.http_client import Http_client


class Module(Scanner, Http_client):
    __info__ = {
        'name': 'iSpy 7.2.2.0 - Authentication Bypass Detection',
        'description': 'iSpy 7.2.2.0 contains an authentication bypass vulnerability. An attacker can craft a URL and possibly obtain sensitive information, modify data, and/or execute unauthorized operations.',
        'author': ['KittySploit Team'],
        'severity': 'critical',
        'tags': ['web', 'scanner', 'cve', 'cve2022', 'ispy', 'auth-bypass', 'ispyconnect', 'vuln'],
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
            'https://gist.github.com/securylight/79f673aa3a453c80c0e78f356a8f650b',
            'https://github.com/securylight/CVES_write_ups/blob/main/iSpy_connect.pdf',
            'https://cve.mitre.org/cgi-bin/cvename.cgi?name=2022-29775',
            'https://nvd.nist.gov/vuln/detail/CVE-2022-29775',
            'https://github.com/securylight/CVES_write_ups',
        ],
        'cve': 'CVE-2022-29775',
    }

    def run(self):
        r = self.http_request(method="GET", path='/logfile?d=crossdomain.xml', allow_redirects=False)
        if not r or r.status_code != 200:
            return False
        body = r.text or ""
        headers = "\n".join(f"{k}: {v}" for k, v in r.headers.items())
        body_all = ('Log Start', 'Log File', 'iSpy',)
        header_any = ('text/html',)
        if (all(m in body for m in body_all)) and (any(m in headers for m in header_any)):
            self.set_info(
                severity='critical',
                reason="iSpy 7.2.2.0 - Authentication Bypass detected",
                path='/logfile?d=crossdomain.xml',
            )
            return True
        return False

