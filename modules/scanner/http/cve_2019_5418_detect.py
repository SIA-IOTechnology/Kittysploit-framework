#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Rails <5."""

import re
from kittysploit import *
from lib.protocols.http.http_client import Http_client


class Module(Scanner, Http_client):
    __info__ = {
        'name': 'Rails File Content Disclosure Detection',
        'description': "Rails <5.2.2.1, <5.1.6.2, <5.0.7.2, <4.2.11.1 and v3 are susceptible to a file content disclosure vulnerability because specially crafted accept headers can cause contents of arbitrary files on the target system's file system to be exposed.",
        'author': ['KittySploit Team'],
        'severity': 'high',
        'tags': ['web', 'scanner', 'cve', 'cve2019', 'rails', 'lfi', 'disclosure', 'edb', 'rubyonrails', 'kev', 'vkev', 'vuln'],
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
            'https://github.com/omarkurt/CVE-2019-5418',
            'https://weblog.rubyonrails.org/2019/3/13/Rails-4-2-5-1-5-1-6-2-have-been-released/',
            'https://nvd.nist.gov/vuln/detail/CVE-2019-5418',
            'https://www.exploit-db.com/exploits/46585/',
            'http://lists.opensuse.org/opensuse-security-announce/2019-05/msg00011.html',
        ],
        'cve': 'CVE-2019-5418',
    }

    def run(self):
        r = self.http_request(method="GET", path='/', allow_redirects=False)
        if not r or r.status_code not in (200, 500):
            return False
        body = r.text or ""
        body_regexes = ('root:.*:0:0:',)
        if (any(re.search(rx, body, 0) for rx in body_regexes)):
            self.set_info(
                severity='high',
                reason="Rails File Content Disclosure detected",
                path='/',
            )
            return True
        return False

