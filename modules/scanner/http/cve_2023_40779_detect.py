#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""An issue in IceWarp Mail Server Deep Castle 2 v."""

import re
from kittysploit import *
from lib.protocols.http.http_client import Http_client


class Module(Scanner, Http_client):
    __info__ = {
        'name': 'IceWarp Mail Server Deep Castle 2 v.13.0.1.2 - Open Redirect Detection',
        'description': 'An issue in IceWarp Mail Server Deep Castle 2 v.13.0.1.2 allows a remote attacker to execute arbitrary code via a crafted request to the URL.',
        'author': ['KittySploit Team'],
        'severity': 'medium',
        'tags': ['web', 'scanner', 'cve', 'cve2023', 'icewarp', 'redirect', 'vuln'],
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
            'https://medium.com/@muthumohanprasath.r/open-redirection-vulnerability-on-icewarp-webclient-product-cve-2023-40779-61176503710',
            'https://nvd.nist.gov/vuln/detail/CVE-2023-40779',
            'https://medium.com/%40muthumohanprasath.r/open-redirection-vulnerability-on-icewarp-webclient-product-cve-2023-40779-61176503710',
        ],
        'cve': 'CVE-2023-40779',
    }

    def run(self):
        r = self.http_request(method="GET", path='/%5coast.pro/%2f%2e%2e', allow_redirects=False)
        if not r or r.status_code != 302:
            return False
        headers = "\n".join(f"{k}: {v}" for k, v in r.headers.items())
        header_regexes = ('(?m)^(?:Location\\s*?:\\s*?)(?:https?://|//)?(?:[a-zA-Z0-9\\-_\\.@]*)oast\\.pro.*$',)
        if (any(re.search(rx, headers, 0) for rx in header_regexes)):
            self.set_info(
                severity='medium',
                reason="IceWarp Mail Server Deep Castle 2 v.13.0.1.2 - Open Redirect detected",
                path='/%5coast.pro/%2f%2e%2e',
            )
            return True
        return False

