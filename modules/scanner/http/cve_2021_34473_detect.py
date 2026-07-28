#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Microsoft Exchange Server is vulnerable to a remote code execution vulnerability."""

from kittysploit import *
from lib.protocols.http.http_client import Http_client


class Module(Scanner, Http_client):
    __info__ = {
        'name': 'Exchange Server - Remote Code Execution Detection',
        'description': 'Microsoft Exchange Server is vulnerable to a remote code execution vulnerability. This CVE ID is unique from CVE-2021-31196, CVE-2021-31206.',
        'author': ['KittySploit Team'],
        'severity': 'critical',
        'tags': ['web', 'scanner', 'cve', 'cve2021', 'ssrf', 'rce', 'exchange', 'kev', 'microsoft', 'vkev', 'vuln'],
        'agent': {
            'risk': 'active',
            'effects': ['network_probe'],
            'expected_requests': 2,
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
            'https://msrc.microsoft.com/update-guide/vulnerability/CVE-2021-34473',
            'https://blog.orange.tw/2021/08/proxylogon-a-new-attack-surface-on-ms-exchange-part-1.html',
            'https://peterjson.medium.com/reproducing-the-proxyshell-pwn2own-exploit-49743a4ea9a1',
            'https://nvd.nist.gov/vuln/detail/CVE-2021-34473',
            'https://portal.msrc.microsoft.com/en-US/security-guidance/advisory/CVE-2021-34473',
        ],
        'cve': 'CVE-2021-34473',
    }

    def run(self):
        for path in ('/autodiscover/autodiscover.json?@test.com/owa/?&Email=autodiscover/autodiscover.json%3F@test.com', '/autodiscover/autodiscover.json?@test.com/mapi/nspi/?&Email=autodiscover/autodiscover.json%3F@test.com'):
            r = self.http_request(method="GET", path=path, allow_redirects=False)
            if not r or r.status_code != 200:
                continue
            body = r.text or ""
            body_any = ('Microsoft.Exchange.Clients.Owa2.Server.Core.OwaADUserNotFoundException', 'Exchange MAPI/HTTP Connectivity Endpoint',)
            if (any(m in body for m in body_any)):
                self.set_info(
                    severity='critical',
                    reason="Exchange Server - Remote Code Execution detected",
                    path=path,
                )
                return True
        return False

