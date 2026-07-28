#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Apache Struts is prone to multiple open-redirection vulnerabilities because the application fails to properly ."""

import re
from kittysploit import *
from lib.protocols.http.http_client import Http_client


class Module(Scanner, Http_client):
    __info__ = {
        'name': 'Apache Struts - Multiple Open Redirection Vulnerabilities Detection',
        'description': 'Apache Struts is prone to multiple open-redirection vulnerabilities because the application fails to properly sanitize user-supplied input.',
        'author': ['KittySploit Team'],
        'severity': 'medium',
        'tags': ['web', 'scanner', 'cve', 'cve2013', 'apache', 'redirect', 'struts', 'edb', 'vuln'],
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
            'https://www.exploit-db.com/exploits/38666',
            'https://nvd.nist.gov/vuln/detail/CVE-2013-2248',
            'https://cwiki.apache.org/confluence/display/WW/S2-017',
            'http://struts.apache.org/release/2.3.x/docs/s2-017.html',
            'http://www.fujitsu.com/global/support/software/security/products-f/interstage-bpm-analytics-201301e.html',
        ],
        'cve': 'CVE-2013-2248',
    }

    def run(self):
        r = self.http_request(method="GET", path='/index.action?redirect:http://www.interact.sh/', allow_redirects=False)
        if not r or r.status_code != 200:
            return False
        headers = "\n".join(f"{k}: {v}" for k, v in r.headers.items())
        header_regexes = ('(?m)^(?:Location\\s*?:\\s*?)(?:https?://|//)?(?:[a-zA-Z0-9\\-_\\.@]*)interact\\.sh.*$',)
        if (any(re.search(rx, headers, 0) for rx in header_regexes)):
            self.set_info(
                severity='medium',
                reason="Apache Struts - Multiple Open Redirection Vulnerabilities detected",
                path='/index.action?redirect:http://www.interact.sh/',
            )
            return True
        return False

