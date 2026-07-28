#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""The Oracle Access Manager portion of Oracle Fusion Middleware (component: OpenSSO Agent) is vulnerable to remo."""

from kittysploit import *
from lib.protocols.http.http_client import Http_client


class Module(Scanner, Http_client):
    __info__ = {
        'name': 'Oracle Access Manager - Remote Code Execution Detection',
        'description': 'The Oracle Access Manager portion of Oracle Fusion Middleware (component: OpenSSO Agent) is vulnerable to remote code execution. Supported versions that are affected are 11.1.2.3.0, 12.2.1.3.0 and 12.2.1.4.0. This is an easily exploitable vulnerability that allows unauthenticated attackers with network access via HTTP to compromise Oracle Access Manager.',
        'author': ['KittySploit Team'],
        'severity': 'critical',
        'tags': ['web', 'scanner', 'cve', 'cve2021', 'oam', 'rce', 'java', 'unauth', 'oracle', 'kev', 'vkev', 'vuln'],
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
            'https://testbnull.medium.com/oracle-access-manager-pre-auth-rce-cve-2021-35587-analysis-1302a4542316',
            'https://nvd.nist.gov/vuln/detail/CVE-2021-35587',
            'https://www.oracle.com/security-alerts/cpujan2022.html',
            'https://github.com/ARPSyndicate/kenzer-templates',
            'https://github.com/GrrrDog/Java-Deserialization-Cheat-Sheet',
        ],
        'cve': 'CVE-2021-35587',
    }

    def run(self):
        r = self.http_request(method="GET", path='/oam/server/opensso/sessionservice', allow_redirects=False)
        if not r or r.status_code != 200:
            return False
        body = (r.text or "").lower()
        headers = "\n".join(f"{k}: {v}" for k, v in r.headers.items()).lower()
        server = (r.headers.get("Server") or r.headers.get("server") or "").lower()
        body_any = ('/oam/pages/css/general.css',)
        header_any = ('x-oracle-dms-ecid', 'x-oracle-dms-rid',)
        if (any(m in body for m in body_any)) and (any(m in headers for m in header_any)):
            self.set_info(
                severity='critical',
                reason="Oracle Access Manager - Remote Code Execution detected",
                path='/oam/server/opensso/sessionservice',
            )
            return True
        return False

