#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""An open redirect vulnerability in remotereporter/load_logfiles."""

import re
from kittysploit import *
from lib.protocols.http.http_client import Http_client


class Module(Scanner, Http_client):
    __info__ = {
        'name': 'Netsweeper 3.0.6 - Open Redirection Detection',
        'description': 'An open redirect vulnerability in remotereporter/load_logfiles.php in Netsweeper before 4.0.5 allows remote attackers to redirect users to arbitrary web sites and conduct phishing attacks via a URL in the url parameter.',
        'author': ['KittySploit Team'],
        'severity': 'medium',
        'tags': ['web', 'scanner', 'cve', 'cve2014', 'netsweeper', 'redirect', 'packetstorm', 'xss', 'vuln'],
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
            'https://packetstormsecurity.com/files/download/133034/netsweeper-issues.tgz',
            'https://nvd.nist.gov/vuln/detail/CVE-2014-9617',
            'http://packetstormsecurity.com/files/133034/Netsweeper-Bypass-XSS-Redirection-SQL-Injection-Execution.html',
            'https://github.com/ARPSyndicate/kenzer-templates',
        ],
        'cve': 'CVE-2014-9617',
    }

    def run(self):
        r = self.http_request(method="GET", path='/remotereporter/load_logfiles.php?server=127.0.0.1&url=https://interact.sh/', allow_redirects=False)
        if not r or r.status_code != 200:
            return False
        headers = "\n".join(f"{k}: {v}" for k, v in r.headers.items())
        server = r.headers.get("Server") or r.headers.get("server") or ""
        header_regexes = ('(?m)^(?:Location\\s*?:\\s*?)(?:https?://|//)(?:[a-zA-Z0-9\\-_\\.@]*)interact\\.sh.*$',)
        if (any(re.search(rx, headers, 0) for rx in header_regexes)):
            self.set_info(
                severity='medium',
                reason="Netsweeper 3.0.6 - Open Redirection detected",
                path='/remotereporter/load_logfiles.php?server=127.0.0.1&url=https://interact.sh/',
            )
            return True
        return False

