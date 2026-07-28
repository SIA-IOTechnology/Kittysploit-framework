#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Open Redirection Vulnerability in the redir."""

import re
from kittysploit import *
from lib.protocols.http.http_client import Http_client


class Module(Scanner, Http_client):
    __info__ = {
        'name': 'Telaen => v1.3.1 - Open Redirect Detection',
        'description': 'Open Redirection Vulnerability in the redir.php script in Telaen before 1.3.1 allows remote attackers to redirect victims to arbitrary websites via a crafted URL.',
        'author': ['KittySploit Team'],
        'severity': 'medium',
        'tags': ['web', 'scanner', 'cve', 'cve2013', 'telaen', 'redirect', 'telaen_project', 'vuln'],
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
            'https://www.exploit-db.com/exploits/38546',
            'https://exchange.xforce.ibmcloud.com/vulnerabilities/84683',
            'https://nvd.nist.gov/vuln/detail/CVE-2013-2621',
        ],
        'cve': 'CVE-2013-2621',
    }

    def run(self):
        for path in ('/telaen/redir.php?https://interact.sh', '/redir.php?https://interact.sh'):
            r = self.http_request(method="GET", path=path, allow_redirects=False)
            if not r or r.status_code != 200:
                continue
            headers = "\n".join(f"{k}: {v}" for k, v in r.headers.items())
            header_regexes = ('(?m)^(?:Location\\s*?:\\s*?)(?:https?://|//)(?:[a-zA-Z0-9\\-_\\.@]*)interact\\.sh.*$',)
            if (any(re.search(rx, headers, 0) for rx in header_regexes)):
                self.set_info(
                    severity='medium',
                    reason="Telaen => v1.3.1 - Open Redirect detected",
                    path=path,
                )
                return True
        return False

