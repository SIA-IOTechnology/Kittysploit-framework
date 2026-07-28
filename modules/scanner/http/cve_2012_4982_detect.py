#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Open redirect vulnerability in assets/login on the Forescout CounterACT NAC device before 7."""

import re
from kittysploit import *
from lib.protocols.http.http_client import Http_client


class Module(Scanner, Http_client):
    __info__ = {
        'name': 'Forescout CounterACT 6.3.4.1 - Open Redirect Detection',
        'description': "Open redirect vulnerability in assets/login on the Forescout CounterACT NAC device before 7.0 allows remote attackers to redirect users to arbitrary web sites and conduct phishing attacks via a URL in the 'a' parameter.",
        'author': ['KittySploit Team'],
        'severity': 'medium',
        'tags': ['web', 'scanner', 'cve', 'cve2012', 'redirect', 'forescout', 'counteract', 'vuln'],
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
            'https://www.exploit-db.com/exploits/38062',
            'https://www.reactionpenetrationtesting.co.uk/forescout-cross-site-redirection.html',
            'https://nvd.nist.gov/vuln/detail/CVE-2012-4982',
            'http://www.reactionpenetrationtesting.co.uk/forescout-cross-site-redirection.html',
            'https://github.com/tr3ss/newclei',
        ],
        'cve': 'CVE-2012-4982',
    }

    def run(self):
        r = self.http_request(method="GET", path='/assets/login?a=https://interact.sh', allow_redirects=False)
        if not r or r.status_code != 200:
            return False
        headers = "\n".join(f"{k}: {v}" for k, v in r.headers.items())
        header_regexes = ('(?m)^(?:Location\\s*?:\\s*?)(?:https?://|//)(?:[a-zA-Z0-9\\-_\\.@]*)interact\\.sh.*$',)
        if (any(re.search(rx, headers, 0) for rx in header_regexes)):
            self.set_info(
                severity='medium',
                reason="Forescout CounterACT 6.3.4.1 - Open Redirect detected",
                path='/assets/login?a=https://interact.sh',
            )
            return True
        return False

