#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Apache Tomcat versions prior to 9."""

import re
from kittysploit import *
from lib.protocols.http.http_client import Http_client


class Module(Scanner, Http_client):
    __info__ = {
        'name': 'Apache Tomcat - Open Redirect Detection',
        'description': 'Apache Tomcat versions prior to 9.0.12, 8.5.34, and 7.0.91 are prone to an open-redirection vulnerability because it fails to properly sanitize user-supplied input.',
        'author': ['KittySploit Team'],
        'severity': 'medium',
        'tags': ['web', 'scanner', 'cve', 'cve2018', 'packetstorm', 'tomcat', 'redirect', 'apache', 'vuln'],
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
            'https://lists.apache.org/thread.html/23134c9b5a23892a205dc140cdd8c9c0add233600f76b313dda6bd75@%3Cannounce.tomcat.apache.org%3E',
            'https://nvd.nist.gov/vuln/detail/CVE-2018-11784',
            'http://lists.opensuse.org/opensuse-security-announce/2019-06/msg00030.html',
            'http://lists.opensuse.org/opensuse-security-announce/2019-07/msg00056.html',
            'http://packetstormsecurity.com/files/163456/Apache-Tomcat-9.0.0M1-Open-Redirect.html',
        ],
        'cve': 'CVE-2018-11784',
    }

    def run(self):
        r = self.http_request(method="GET", path='//interact.sh', allow_redirects=False)
        if not r or r.status_code != 404:
            return False
        headers = "\n".join(f"{k}: {v}" for k, v in r.headers.items())
        header_regexes = ('(?m)^(?:Location\\s*?:\\s*?)(?:https?:\\/\\/|\\/\\/|\\/\\\\\\\\|\\/\\\\)(?:[a-zA-Z0-9\\-_\\.@]*\\.)?interact\\.sh\\/?(\\/.*)?$',)
        if (any(re.search(rx, headers, 0) for rx in header_regexes)):
            self.set_info(
                severity='medium',
                reason="Apache Tomcat - Open Redirect detected",
                path='//interact.sh',
            )
            return True
        return False

