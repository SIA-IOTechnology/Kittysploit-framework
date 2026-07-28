#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""ForgeRock AM server before 7."""

from kittysploit import *
from lib.protocols.http.http_client import Http_client


class Module(Scanner, Http_client):
    __info__ = {
        'name': 'ForgeRock OpenAM <7.0 - Remote Code Execution Detection',
        'description': 'ForgeRock AM server before 7.0 has a Java deserialization vulnerability in the jato.pageSession parameter on multiple pages. The exploitation does not require authentication, and remote code execution can be triggered by sending a single crafted /ccversion/* request to the server. The vulnerability exists due to the usage of Sun ONE Application Framework (JATO) found in versions of Java 8 or earlier.',
        'author': ['KittySploit Team'],
        'severity': 'critical',
        'tags': ['web', 'scanner', 'cve', 'cve2021', 'packetstorm', 'openam', 'rce', 'java', 'kev', 'forgerock', 'vkev', 'vuln'],
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
            'https://portswigger.net/research/pre-auth-rce-in-forgerock-openam-cve-2021-35464',
            'https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2021-35464',
            'http://packetstormsecurity.com/files/163486/ForgeRock-OpenAM-Jato-Java-Deserialization.html',
            'http://packetstormsecurity.com/files/163525/ForgeRock-Access-Manager-OpenAM-14.6.3-Remote-Code-Execution.html',
            'https://bugster.forgerock.org',
        ],
        'cve': 'CVE-2021-35464',
    }

    def run(self):
        r = self.http_request(method="GET", path='/openam/oauth2/..;/ccversion/Version', allow_redirects=False)
        if not r or r.status_code != 200:
            return False
        body = r.text or ""
        headers = "\n".join(f"{k}: {v}" for k, v in r.headers.items())
        body_any = ('Version Information -', 'openam/ccversion/Masthead.jsp',)
        header_any = ('Set-Cookie: JSESSIONID=',)
        if (any(m in body for m in body_any)) and (any(m in headers for m in header_any)):
            self.set_info(
                severity='critical',
                reason="ForgeRock OpenAM <7.0 - Remote Code Execution detected",
                path='/openam/oauth2/..;/ccversion/Version',
            )
            return True
        return False

