#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""PTZOptics camera insufficient auth leaking password hash (CVE-2024-8956 / CVE-2024-8957)."""

import re
from kittysploit import *
from lib.protocols.http.http_client import Http_client


class Module(Scanner, Http_client):
    __info__ = {
        'name': 'PTZOptics Camera - Unauth System Config / Password Leak (CVE-2024-8956)',
        'description': (
            'PTZOptics cameras expose /cgi-bin/param.cgi?get_system_conf without authentication, '
            'leaking userpasswd hashes (CVE-2024-8956). Presence also indicates the related '
            'OS command injection CVE-2024-8957.'
        ),
        'author': ['KittySploit Team'],
        'severity': 'critical',
        'tags': [
            'web', 'scanner', 'cve', 'cve2024', 'ptzoptics', 'camera', 'iot',
            'exposure', 'unauth', 'kev', 'vuln',
        ],
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
                'produces_capabilities': [{'capability': 'admin_surface', 'from_detail': ''}],
                'consumes_capabilities': [],
                'option_bindings': {},
                'suggested_followups': ['exploits/linux/http/ptzoptics_cve_2024_8957_rce'],
            },
        },
        'references': [
            'https://ptzoptics.com/known-vulnerabilities-and-fixes/',
            'https://vulncheck.com/advisories/ptzoptics-insufficient-auth',
            'https://www.cisa.gov/news-events/ics-advisories/icsa-25-162-10',
            'https://nvd.nist.gov/vuln/detail/CVE-2024-8956',
        ],
        'cve': 'CVE-2024-8956',
    }

    def run(self):
        path = '/cgi-bin/param.cgi?get_system_conf'
        r = self.http_request(method='GET', path=path, allow_redirects=False)
        if not r or r.status_code != 200:
            return False
        body = r.text or ''
        if re.search(r'userpasswd="[a-f0-9]+"', body):
            self.set_info(
                severity='critical',
                reason='PTZOptics CVE-2024-8956 unauthenticated password hash disclosure',
                path=path,
            )
            return True
        return False
